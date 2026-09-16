rule GoldenEye_Ransomware_XLS_RID3061 : CRIME DEMO FILE MAL RANSOM T1203 T1566_001 {
   meta:
      description = "GoldenEye XLS with Macro - file Schneider-Bewerbung.xls"
      author = "Florian Roth"
      reference = "https://www.heise.de/news/Aufgepasst-Neuer-Verschluesselungstrojaner-Goldeneye-verbreitet-sich-rasant-3561396.html"
      date = "2016-12-06 12:37:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "2320d4232ee80cc90bacd768ba52374a21d0773c39895b88cdcaa7782e16c441"
      tags = "CRIME, DEMO, FILE, MAL, RANSOM, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "fso.GetTempName();tmp_path = tmp_path.replace('.tmp', '.exe')" fullword ascii
      $x2 = "var shell = new ActiveXObject('WScript.Shell');shell.run(t'" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 and filesize < 4000KB and 1 of them )
}