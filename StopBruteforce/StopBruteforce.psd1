#
# Манифест модуля для модуля "StopBruteforce".
#
# Создано: Ilya
#
# Дата создания: 09.02.2022
#

@{

# Файл модуля сценария или двоичного модуля, связанный с этим манифестом.
RootModule = 'StopBruteforce.dll'

# Номер версии данного модуля.
ModuleVersion = '1.0.6'

# Поддерживаемые выпуски PSEditions
# CompatiblePSEditions = @()

# Уникальный идентификатор данного модуля
GUID = '269dd410-770b-4d5f-9593-7baf1650a8b0'

# Автор данного модуля
Author = 'Ilya'

# Компания, создавшая данный модуль, или его поставщик
CompanyName = 'Ruvds'

# Заявление об авторских правах на модуль
Copyright = 'Copyright (c) 2020 nneeoo'

# Описание функций данного модуля
Description = 'PSStopBruteforce modules to stop bruteforce attack on SMB, RDP and WinRm'

# Минимальный номер версии обработчика Windows PowerShell, необходимой для работы данного модуля
# PowerShellVersion = ''

# Имя узла Windows PowerShell, необходимого для работы данного модуля
# PowerShellHostName = ''

# Минимальный номер версии узла Windows PowerShell, необходимой для работы данного модуля
# PowerShellHostVersion = ''

# Минимальный номер версии Microsoft .NET Framework, необходимой для данного модуля. Это обязательное требование действительно только для выпуска PowerShell, предназначенного для компьютеров.
# DotNetFrameworkVersion = ''

# Минимальный номер версии среды CLR (общеязыковой среды выполнения), необходимой для работы данного модуля. Это обязательное требование действительно только для выпуска PowerShell, предназначенного для компьютеров.
# CLRVersion = ''

# Архитектура процессора (нет, X86, AMD64), необходимая для этого модуля
# ProcessorArchitecture = ''

# Модули, которые необходимо импортировать в глобальную среду перед импортированием данного модуля
# RequiredModules = @()

# Сборки, которые должны быть загружены перед импортированием данного модуля
# RequiredAssemblies = @()

# Файлы сценария (PS1), которые запускаются в среде вызывающей стороны перед импортом данного модуля.
# ScriptsToProcess = @()

# Файлы типа (.ps1xml), которые загружаются при импорте данного модуля
# TypesToProcess = @()

# Файлы формата (PS1XML-файлы), которые загружаются при импорте данного модуля
# FormatsToProcess = @()

# Модули для импорта в качестве вложенных модулей модуля, указанного в параметре RootModule/ModuleToProcess
# NestedModules = @()

# В целях обеспечения оптимальной производительности функции для экспорта из этого модуля не используют подстановочные знаки и не удаляют запись. Используйте пустой массив, если нет функций для экспорта.
FunctionsToExport = @()

# В целях обеспечения оптимальной производительности командлеты для экспорта из этого модуля не используют подстановочные знаки и не удаляют запись. Используйте пустой массив, если нет командлетов для экспорта.
CmdletsToExport = @("Get-Bruteforce","Protect-FromBruteforce","Stop-Bruteforce","Unprotect-FromBruteforce")

# Переменные для экспорта из данного модуля
VariablesToExport = '*'

# В целях обеспечения оптимальной производительности псевдонимы для экспорта из этого модуля не используют подстановочные знаки и не удаляют запись. Используйте пустой массив, если нет псевдонимов для экспорта.
AliasesToExport = @()

# Ресурсы DSC для экспорта из этого модуля
# DscResourcesToExport = @()

# Список всех модулей, входящих в пакет данного модуля
# ModuleList = @()

# Список всех файлов, входящих в пакет данного модуля
# FileList = @()

# Личные данные для передачи в модуль, указанный в параметре RootModule/ModuleToProcess. Он также может содержать хэш-таблицу PSData с дополнительными метаданными модуля, которые используются в PowerShell.
PrivateData = @{

    PSData = @{

        # Теги, применимые к этому модулю. Они помогают с обнаружением модуля в онлайн-коллекциях.
        # Tags = @()

        # URL-адрес лицензии для этого модуля.
        LicenseUri = 'https://opensource.org/licenses/MIT'

        # URL-адрес главного веб-сайта для этого проекта.
        ProjectUri = 'https://github.com/nneeoo/PSStopBruteforce'

        # URL-адрес значка, который представляет этот модуль.
        # IconUri = ''

        # Заметки о выпуске этого модуля
        ReleaseNotes = '
### 1.0.6
- New cmdlet defaults 
- Slight performance improvements
- Add target for .net framework 4.8
        
### 1.0.5
- Slightly faster event log search
- Cmdlets write warnings if nothing happened
- Get-Bruteforce now collect usernames 
- Add Cmdlet input validation
- Fix false warnings

### 1.0.4

- Protect-FromBruteforce - do nothing if no network logons was found
- Add warnings if cmdlet did nothing
- Write warnings if one of the steps fails
- Update module manifest

### 1.0.3

- fix error when input array is empty
- Move unnecessary messages to verbose

### 1.0.2

- Add binary modules

### 1.0.1

- Better naming for modules
- Remove redundant type casting

## 1.0.0

- Initial Commit'

    } # Конец хэш-таблицы PSData

} # Конец хэш-таблицы PrivateData

# Код URI для HelpInfo данного модуля
HelpInfoURI = 'https://github.com/nneeoo/PSStopBruteforce/wiki'

# Префикс по умолчанию для команд, экспортированных из этого модуля. Переопределите префикс по умолчанию с помощью команды Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

