# Рекомендуемый фильтр Procmon
recommended-procmon.pmc — это бинарная конфигурация Procmon, использовавшаяся в протестированном развёртывании CAPE.
SHA-256:
1867d381ed5be68928f301d7796ca449948dc9401aea94dd4313b0b24913d27b

# Самая важная настройка:
Filter → Drop Filtered Events
Без неё Procmon может продолжать сохранять многогигабайтный PML-файл, даже если экспортный фильтр настроен достаточно узко.
Протестированный профиль включает следующие полезные операции:
- Process Create
- Process Exit
- Load Image
- CreateFile
- ReadFile
- WriteFile
- SetDispositionInformationFile
- SetRenameInformationFile
- SetBasicInformationFile
- SetEndOfFileInformationFile
- CreatePipe
- RegCreateKey
- RegSetValue
- RegDeleteValue
- RegRenameKey
- TCP Connect

Профиль исключает типичный  шум от системы  , а также малополезные высокочастотные события.
Если ваша версия Procmon не принимает приложенный PMC-файл, создайте аналогичный фильтр вручную в Procmon и сохраните его под именем:
procmon.pmc

Перед замной конфигурации CAPE рекомендуется сохранить резервную копию:
cd /opt/CAPEv2

cp analyzer/windows/bin/procmon.pmc \
   analyzer/windows/bin/procmon.pmc.bak

cp /path/to/recommended-procmon.pmc \
   analyzer/windows/bin/procmon.pmc

chown cape:cape analyzer/windows/bin/procmon.pmc
chmod 0644 analyzer/windows/bin/procmon.pmc

Не распространяйте Microsoft procmon.exe в составе этого репозитория.
Исспользуйте Procmon в соответствии с условиями лицензирования Microsoft Sysinternals и способом установки, используемым в вашей CAPE-среде.
