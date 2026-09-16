rule Suspicious_Script_Running_from_HTTP_RID350E : DEMO SCRIPT T1059 {
   meta:
      description = "Detects a suspicious "
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/a112274e109c5819d54aa8de89b0e707b243f4929a83e77439e3ff01ed218a35?environmentId=100"
      date = "2017-08-20 15:56:51"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd /C script:http://" ascii nocase
      $s2 = "cmd /C script:https://" ascii nocase
      $s3 = "cmd.exe /C script:http://" ascii nocase
      $s4 = "cmd.exe /C script:https://" ascii nocase
   condition: 
      1 of them
}