SQL Injection Scoring
=====================

![This script was last tested in Nuix 7.8](https://img.shields.io/badge/Script%20Tested%20in%20Nuix-7.8-green.svg)

View the GitHub project [here](https://github.com/Nuix/SQL-Injection-Scoring) or download the latest release [here](https://github.com/Nuix/SQL-Injection-Scoring/releases).

# Overview

This project looks to identify and score potential SQL injections.  This is accomplished using a Worker Side Script.  When an item is of mime type `text/x-common-log-entry` or `application/vnd.ms-iis-log-entry`, it then looks to match 1 or more regular expressions against the properties metadata of an item, assigning a score related to each regular expression.

| Regular Expression | Score |
|--------------------|-------|
| `or[0-9A-F%\s\(\/*]+\d=\d` | 25 |
| `like[\s%0-9A-F\/*]+['"]%` | 50 |
| `or[0-9%A-F\s\/*]+['"].['"]=['"]` | 25 |
| `sleep[\s%0-9A-F\/*]+\d` | 50 |
| `waitfor[%0-9A-F\s\/*]+delay` | 75 |
| `select[\s%A-F0-9\/*]+` | 50 |
| `union.*?select` | 75 |
| `exec[\s%A-F0-9\/*]+(xp|sp|master)` | 75 |
| `--` | 10 |

The resulting score is then recorded as a custom metadata field named `SQLi Score` against the item.  If the score is greater than 100, the item will also have a tag named `CTAT Intel/SQLi Detected` applied.

# Getting Started

## Setup

Begin by downloading the latest release of this project.  Copy the file [Find Probable SQLi.xml](https://github.com/Nuix/SQL-Injection-Scoring/blob/master/Project/Find%20Probable%20SQLi.xml) to your saved searches directory.  On a Windows machine this will likely be either of the following:

- `%appdata%\Nuix\Saved Searches` - User level directory
- `%programdata%\Nuix\Saved Searches` - System level directory

**Warning!** Placing a saved search in a global directory makes it accessible to all Nuix users, however, it also potentially makes it editable by all users.  If a change is made by a single user to a saved search that generates an error, that error can impact all users on the system. 

Once the saved search is dropped into the Nuix Saved Searches directory, it appears on the Go tab under Load Search as Find Probable SQLi. 

## Processing Data

1. In Nuix Workstation, create a new case and specify your evidence.
2. Open the **Evidence Processing Settings** dialog.
3. On the **Evidence Processing Settings** dialog under **Family Text Settings**, ensure that the check box for **Hide immaterial items (text rolled up to parent)** is cleared.
4. Under **Item Content Settings**, ensure that the check boxes for **Extract named entities from text** is selected.
5. Click **OK**.
6. On the **Evidence Processing Settings** dialog, click the **Worker Script** tab.
7. Select the **ruby** radio button and paste the contents of [WSS_SQLi_Scoring.rb](https://github.com/Nuix/SQL-Injection-Scoring/blob/master/Project/WSS_SQLi_Scoring.rb) into the text field.
8. Click **OK** and finish ingesting the evidence you have specified.

## Reviewing the Results

After ingestion has completed, run the saved search.

![image](https://user-images.githubusercontent.com/11775738/53524475-55c42700-3a94-11e9-83a4-6a154d9b8d89.png)

Items with a score greater than 100 will also have a tag named `CTAT Intel/SQLi Detected` applied to them during processing.

The resulting metadata indicates if any SQLi has been found.

![image](https://user-images.githubusercontent.com/11775738/53524527-75f3e600-3a94-11e9-96a0-df925da6f785.png)

# License

```
Copyright 2019 Nuix

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```