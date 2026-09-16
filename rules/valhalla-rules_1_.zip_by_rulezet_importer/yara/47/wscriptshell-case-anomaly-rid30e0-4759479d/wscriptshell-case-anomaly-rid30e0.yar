rule WScriptShell_Case_Anomaly_RID30E0 : ANOMALY DEMO OBFUS SCRIPT SUSP T1059 {
   meta:
      description = "Detects obfuscated wscript.shell commands"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-11 12:58:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-06-09"
      tags = "ANOMALY, DEMO, OBFUS, SCRIPT, SUSP, T1059"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WScript.Shell\").Run" nocase ascii wide
      $sn1 = "WScript.Shell\").Run" ascii wide
      $sn2 = "wscript.shell\").run" ascii wide
      $sn3 = "WSCRIPT.SHELL\").RUN" ascii wide
      $sn4 = "Wscript.Shell\").Run" ascii wide
      $sn5 = "WScript.shell\").Run" ascii wide
   condition: 
      filesize < 3000KB and #s1 > #sn1 + #sn2 + #sn3 + #sn4 + #sn5
}