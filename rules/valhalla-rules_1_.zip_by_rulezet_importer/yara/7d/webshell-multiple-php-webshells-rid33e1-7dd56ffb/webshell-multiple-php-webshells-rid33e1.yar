rule Webshell_multiple_php_webshells_RID33E1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files multiple_php_webshells"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:06:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "911195a9b7c010f61b66439d9048f400"
      hash2 = "be0f67f3e995517d18859ed57b4b4389"
      hash3 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI" 
      $s2 = "sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0" 
      $s4 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg" 
   condition: 
      2 of them
}