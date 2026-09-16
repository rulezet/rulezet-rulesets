rule Webshell_FSO_s_ajan_2_RID2EEA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ajan.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")" 
      $s3 = "/file.zip" 
   condition: 
      all of them
}