
# CAPEv2-Sandbox-plugin Procmon-Events Investigation UI

Расширение WebUI для CAPEv2: добавляет в обычный отчёт вкладку **Procmon Events** и позволяет нормально работать с  `procmon.xml` как с "журналом" расследования.

> Это community WebUI extension/patch, а не официальный plugin API CAPE.

## Возможности


<img width="2552" height="925" alt="1- Общий вид" src="https://github.com/user-attachments/assets/be81ca2a-ff9b-4fef-8c4d-2912a17d18d0" />




- вкладка **Procmon Events** в отчёте CAPE;
- серверная пагинация 25 / 50 / 100 / 200 событий;
- SQLite-кэш для XML на сотни мегабайт;
- клик по событию открывает подробную карточку;
- Command Line, Parent Process/PID, User, Integrity, Image Path;
- показ всех дополнительных полей Procmon XML;
- рекурсивный поиск по событию и метаданным процесса;
- поиск по параметрам: `operation:`, `cmd:`, `parent:`, `pid:` и т.д.;
- поиск по произвольному XML-полю, например `ProcessIndex:105`;
- Copy JSON / Copy path / Related PID;
- backup + автоматический rollback при ошибке установки;
- миграция базы CAPE не требуется.


<img width="705" height="816" alt="2 Вид карточки" src="https://github.com/user-attachments/assets/c0cfff52-eb62-4153-9605-05128c4cd060" />




## Источник данных:

```text
storage/analyses/<TASK_ID>/aux/procmon.xml
```

## Установка

Скачайте или клонируйте репозиторий на CAPE host и запускай от владельца дерева CAPE (обычно `cape`):

```bash
cd cape-procmon-investigation-ui
python3 install.py --root /opt/CAPEv2
sudo systemctl restart cape-web
systemctl is-active cape-web
```

Installer проверяет Python, Django, шаблоны, backend на синтетическом Procmon XML и `git diff --check`. Если проверка падает, CAPE автоматически возвращается к состоянию до установки.

Можно сразу перезапустить WebUI:

```bash
python3 install.py --root /opt/CAPEv2 --restart
```

## Что должно быть включено в CAPE

Procmon auxiliary должен реально создавать XML:

```ini
[auxiliary_modules]
procmon = yes
```

Processing-модуль тоже лучше оставить включённым:

```ini
[procmon]
enabled = yes
```

Для больших XML может понадобиться увеличить ResultServer upload limit. Подробности: [CONFIGURATION_RU.md).

## Поиск

Примеры:

```text
powershell WriteFile
"ExecutionPolicy Bypass"
cmd:"ExecutionPolicy Bypass"
operation:RegSetValue
parent:EXCEL.EXE
pid:4408
integrity:High
ProcessIndex:105
```

Несколько выражений работают как AND. Фраза в кавычках ищется целиком. Неизвестный `FieldName:value` ищется по всем сырым XML-полям.

## Удаление

```bash
python3 uninstall.py --root /opt/CAPEv2
sudo systemctl restart cape-web
```

Удалить также временный индекс:

```bash
python3 uninstall.py --root /opt/CAPEv2 --clear-cache
```

Backup хранится в `/opt/CAPEv2/.procmon-ui-backups/`.

## Опциональный stability fix

В  папке `extras/` находится отдельный фикс для старых версий CAPE, где Procmon зависает на `/Terminate`/экспорте или пишет гигантский PML. Он **не нужен для самой WebUI-вкладки** и специально отказывается патчить неизвестную версию `procmon.py`.

Там же лежит протестированный `recommended-procmon.pmc` с включённым **Drop Filtered Events**. Microsoft `procmon.exe` в репозиторий не входит.

## Совместимость

Тестировалось на структуре CAPEv2, актуальной в октябре 2026. CAPE развивается быстро, поэтому installer не пытается «угадывать» при изменении upstream-файлов: при несовпадении anchor'ов он останавливается и делает rollback.

## Лицензия

GPL-3.0. CAPEv2 и Microsoft Sysinternals Procmon — отдельные проекты со своими правообладателями и условиями лицензирования.
