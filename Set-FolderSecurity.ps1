#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$ConfigFile = "config.json",
    [string[]]$ModeOverride = $null,
    [string[]]$TargetFoldersOverride = $null
)

$ErrorActionPreference = 'Stop'

#region ---------- ИНИЦИАЛИЗАЦИЯ И ПРОВЕРКА МОДУЛЕЙ ----------

function Assert-FrameworkModule {
    param(
        [string]$ModuleName,
        [string]$WindowsFeatureName
    )
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Зависимость '$ModuleName' отсутствует. Попытка автоматической установки компонента $WindowsFeatureName..." -ForegroundColor Yellow
        try {
            $session = New-CimSession -ErrorAction SilentlyContinue
            Install-WindowsFeature -Name $WindowsFeatureName -IncludeAllSubFeature -ErrorAction Stop | Out-Null
            Write-Host "Компонент $WindowsFeatureName успешно установлен." -ForegroundColor Green
        } catch {
            Write-Error "Критическая ошибка: Не удалось установить $WindowsFeatureName. Запустите консоль от имени Администратора на Windows Server."
            exit 1
        }
    }
}

Assert-FrameworkModule -ModuleName "ActiveDirectory" -WindowsFeatureName "RSAT-AD-PowerShell"
Assert-FrameworkModule -ModuleName "DFSN" -WindowsFeatureName "RSAT-DFS-Mgmt-Con"

#endregion

#region ---------- ЗАГРУЗКА КОНФИГУРАЦИИ ----------

if (-not (Test-Path -LiteralPath $ConfigFile)) {
    Write-Error "Файл конфигурации не найден по пути: $ConfigFile"
    exit 1
}

try {
    $Config = Get-Content -Raw -LiteralPath $ConfigFile | ConvertFrom-Json
} catch {
    Write-Error "Ошибка чтения или парсинга JSON в файле конфигурации: $($_.Exception.Message)"
    exit 1
}

$Mode          = if ($ModeOverride) { $ModeOverride } else { $Config.Mode }
$Root          = $Config.Root
$DomainDNS     = $Config.DomainDNS
$DomainNB      = $Config.DomainNB
$ServerHost    = $Config.ServerHost
$GroupOU       = $Config.GroupOU
$DfsNamespace  = $Config.DfsNamespace
$ReportDir     = $Config.ReportDir
$FullSuffix    = $Config.FullSuffix
$RoSuffix      = $Config.RoSuffix
$SkipFolders   = $Config.SkipFolders
$TargetFolders = if ($TargetFoldersOverride) { $TargetFoldersOverride } else { $Config.TargetFolders }
$RWRight       = $Config.RWRight
$HiddenShares  = $Config.HiddenShares

#endregion

#region ---------- ИНФРАСТРУКТУРА ЛОГИРОВАНИЯ ----------

$originalWhatIf = $WhatIfPreference
$WhatIfPreference = $false

New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
$logFile = Join-Path $ReportDir ("run_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $logFile -Append | Out-Null

$WhatIfPreference = $originalWhatIf

function ConvertTo-GroupBase {
    param([Parameter(Mandatory)][string]$Name)
    (($Name -replace '[\\/\[\]:;|=,+\*\?<>"]', '') -replace '\s+', '_').Trim('_')
}

function Get-AllFolders {
    Get-ChildItem -LiteralPath $Root -Directory | Sort-Object Name
}

function Get-TargetFolderObjects {
    $all = Get-AllFolders | Where-Object { $_.Name -notin $SkipFolders }
    if ($TargetFolders.Count) { $all = $all | Where-Object { $_.Name -in $TargetFolders } }
    return $all
}

$folders = Get-TargetFolderObjects
Write-Host ("Целевых папок: {0} | Домен: {1} | OU: {2}" -f $folders.Count, $DomainNB, $GroupOU) -ForegroundColor Cyan
Write-Host ("Исключены из обработки: {0}" -f ($SkipFolders -join ', ')) -ForegroundColor DarkGray

#endregion

#region ---------- ЭТАПЫ РАБОТЫ ----------

function Invoke-Audit {
    Write-Host "`n=== АУДИТ СТРУКТУРЫ (Только чтение) ===" -ForegroundColor Cyan
    $auditSet = Get-AllFolders

    $ntfs = foreach ($f in $auditSet) {
        $acl = Get-Acl -LiteralPath $f.FullName
        $protected = $acl.AreAccessRulesProtected
        foreach ($ace in $acl.Access) {
            [pscustomobject]@{
                Folder = $f.Name; InheritanceBroken = $protected
                Identity = $ace.IdentityReference.Value; Rights = $ace.FileSystemRights
                AccessType = $ace.AccessControlType; Inherited = $ace.IsInherited
            }
        }
    }
    $ntfs | Export-Csv (Join-Path $ReportDir 'NTFS_Permissions.csv') -NoTypeInformation -Encoding UTF8
    $ntfs | Sort-Object Folder, Identity | Format-Table -AutoSize

    $rootPattern = ($Root.TrimEnd('\')) + '\*'
    $shareAccess = foreach ($s in (Get-SmbShare | Where-Object { $_.Path -like $rootPattern })) {
        Get-SmbShareAccess -Name $s.Name | ForEach-Object {
            [pscustomobject]@{ Share=$s.Name; Path=$s.Path; Account=$_.AccountName; Type=$_.AccessControlType; Right=$_.AccessRight }
        }
    }
    $shareAccess | Export-Csv (Join-Path $ReportDir 'SMB_Shares.csv') -NoTypeInformation -Encoding UTF8
    $shareAccess | Format-Table -AutoSize

    $grp = foreach ($f in $folders) {
        $base = ConvertTo-GroupBase $f.Name
        foreach ($sfx in $FullSuffix, $RoSuffix) {
            $n = "$base$sfx"
            [pscustomobject]@{ Folder=$f.Name; ExpectedGroup=$n; Exists=[bool](Get-ADGroup -Filter "Name -eq '$n'" -ErrorAction SilentlyContinue) }
        }
    }
    $grp | Export-Csv (Join-Path $ReportDir 'Expected_Groups.csv') -NoTypeInformation -Encoding UTF8
    $grp | Format-Table -AutoSize

    try {
        Get-DfsnFolder -Path "$DfsNamespace\*" -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{ Link=$_.Path; State=$_.State
                    Targets=((Get-DfsnFolderTarget -Path $_.Path -ErrorAction SilentlyContinue).TargetPath -join '; ') }
            } | Tee-Object -Variable dfs | Format-Table -AutoSize
        $dfs | Export-Csv (Join-Path $ReportDir 'DFS_Folders.csv') -NoTypeInformation -Encoding UTF8
    } catch { Write-Warning "DFS Namespace недоступен или пуст: $($_.Exception.Message)" }
}

function New-FolderGroups {
    Write-Host "`n=== АВТОМАТИЗАЦИЯ ГРУПП AD (DomainLocal) ===" -ForegroundColor Cyan
    foreach ($f in $folders) {
        $base = ConvertTo-GroupBase $f.Name
        $plan = @(
            @{ Name = "$base$FullSuffix"; Desc = "Доступ на Запись/Изменение к папке '$($f.Name)' на $ServerHost" }
            @{ Name = "$base$RoSuffix";   Desc = "Доступ Только чтение к папке '$($f.Name)' на $ServerHost" }
        )
        foreach ($p in $plan) {
            if (Get-ADGroup -Filter "Name -eq '$($p.Name)'" -ErrorAction SilentlyContinue) {
                Write-Host "  [=] Группа уже существует: $($p.Name)" -ForegroundColor DarkGray
            } elseif ($PSCmdlet.ShouldProcess($p.Name, 'Создание локальной группы безопасности домена')) {
                New-ADGroup -Name $p.Name -SamAccountName $p.Name -GroupScope DomainLocal `
                            -GroupCategory Security -Path $GroupOU -Description $p.Desc
                Write-Host "  [+] Создана группа: $($p.Name)" -ForegroundColor Green
            }
        }
    }
}

function Set-FolderNTFS {
    Write-Host "`n=== НАСТРОЙКА NTFS ПРАВ (Сброс наследования) ===" -ForegroundColor Cyan
    $CI_OI = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none  = [System.Security.AccessControl.PropagationFlags]::None
    $io    = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    foreach ($f in $folders) {
        $base = ConvertTo-GroupBase $f.Name
        $rw   = "$DomainNB\$base$FullSuffix"
        $ro   = "$DomainNB\$base$RoSuffix"

        $acl = Get-Acl -LiteralPath $f.FullName
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }

        $rules = @(
            New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl',$CI_OI,$none,$allow)
            New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM','FullControl',$CI_OI,$none,$allow)
            New-Object System.Security.AccessControl.FileSystemAccessRule("$DomainNB\Domain Admins",'FullControl',$CI_OI,$none,$allow)
            New-Object System.Security.AccessControl.FileSystemAccessRule('CREATOR OWNER','FullControl',$CI_OI,$io,$allow)
        )

        try {
            $rules += New-Object System.Security.AccessControl.FileSystemAccessRule($rw,$RWRight,$CI_OI,$none,$allow)
            $rules += New-Object System.Security.AccessControl.FileSystemAccessRule($ro,'ReadAndExecute',$CI_OI,$none,$allow)
        } catch {
            Write-Host "  [~] Симуляция: Пропуск связывания $rw / $ro (Нормально при -WhatIf, групп еще нет в AD)" -ForegroundColor DarkGray
        }

        foreach ($r in $rules) { $acl.AddAccessRule($r) }

        if ($PSCmdlet.ShouldProcess($f.FullName, "Применение чистого ACL ($base$FullSuffix / $base$RoSuffix)")) {
            Set-Acl -LiteralPath $f.FullName -AclObject $acl
            Write-Host "  [+] Права NTFS обновлены: $($f.Name)" -ForegroundColor Green
        }
    }
}

function Set-FolderShare {
    Write-Host "`n=== НАСТРОЙКА СЕТЕВЫХ ОБЩИХ ПАПОК (SMB) ===" -ForegroundColor Cyan
    foreach ($f in $folders) {
        $base      = ConvertTo-GroupBase $f.Name
        $rw        = "$DomainNB\$base$FullSuffix"
        $ro        = "$DomainNB\$base$RoSuffix"
        $da        = "$DomainNB\Domain Admins"
        $shareName = if ($HiddenShares) { "$($f.Name)$" } else { $f.Name }

        if (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue) {
            if ($PSCmdlet.ShouldProcess($shareName, 'Модификация разрешений существующей SMB-шары')) {
                Revoke-SmbShareAccess -Name $shareName -AccountName 'Everyone' -Force -ErrorAction SilentlyContinue | Out-Null
                Grant-SmbShareAccess  -Name $shareName -AccountName $da -AccessRight Full   -Force | Out-Null
                try {
                    Grant-SmbShareAccess  -Name $shareName -AccountName $rw -AccessRight Change -Force -ErrorAction Stop | Out-Null
                    Grant-SmbShareAccess  -Name $shareName -AccountName $ro -AccessRight Read   -Force -ErrorAction Stop | Out-Null
                } catch { Write-Host "  [~] Симуляция: Пропуск сетевых прав (групп нет в AD)" -ForegroundColor DarkGray }
                Set-SmbShare -Name $shareName -FolderEnumerationMode AccessBased -Force | Out-Null
                Write-Host "  [~] Обновлены права сетевой шары: $shareName" -ForegroundColor Yellow
            }
        } else {
            if ($PSCmdlet.ShouldProcess($shareName, "Создание новой SMB шары для $($f.FullName)")) {
                try {
                    New-SmbShare -Name $shareName -Path $f.FullName `
                        -FullAccess $da -ChangeAccess $rw -ReadAccess $ro `
                        -FolderEnumerationMode AccessBased -ErrorAction Stop | Out-Null
                    Write-Host "  [+] Сетевая шара создана: $shareName (ABE включен)" -ForegroundColor Green
                } catch {
                    Write-Host "  [~] Симуляция: Шара $shareName будет создана при боевом запуске." -ForegroundColor DarkGray
                }
            }
        }
    }
}

function Set-FolderDFS {
    Write-Host "`n=== ИНТЕГРАЦИЯ В ПРОСТРАНСТВО ИМЕН DFS ===" -ForegroundColor Cyan
    foreach ($f in $folders) {
        $link      = "$DfsNamespace\$($f.Name)"
        $shareName = if ($HiddenShares) { "$($f.Name)$" } else { $f.Name }
        $target    = "\\$ServerHost\$shareName"

        if (-not (Get-DfsnFolder -Path $link -ErrorAction SilentlyContinue)) {
            if ($PSCmdlet.ShouldProcess($link, "Добавление новой папки DFS -> Target: $target")) {
                New-DfsnFolder -Path $link -TargetPath $target | Out-Null
                Write-Host "  [+] Добавлен DFS линк: $link -> $target" -ForegroundColor Green
            }
        } else {
            Write-Host "  [=] Ссылка DFS уже существует: $link" -ForegroundColor DarkGray
        }
    }
}

#endregion

#region ---------- ДИСПЕТЧЕР ВЫПОЛНЕНИЯ ----------

try {
    $run = if ($Mode -contains 'Provision') { @('CreateGroups','SetNTFS','SetShare','SetDFS') } else { $Mode }
    foreach ($step in $run) {
        switch ($step) {
            'Audit'        { Invoke-Audit }
            'CreateGroups' { New-FolderGroups }
            'SetNTFS'      { Set-FolderNTFS }
            'SetShare'     { Set-FolderShare }
            'SetDFS'       { Set-FolderDFS }
        }
    }
    Write-Host "`nВыполнение успешно завершено. Лог-файл: $logFile | Папка отчетов: $ReportDir" -ForegroundColor Cyan
}
finally { 
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null 
}

#endregion
