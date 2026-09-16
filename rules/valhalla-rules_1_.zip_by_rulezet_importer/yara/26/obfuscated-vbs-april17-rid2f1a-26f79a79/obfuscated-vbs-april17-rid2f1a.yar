rule Obfuscated_VBS_April17_RID2F1A : ANOMALY DEMO HKTL OBFUS S0002 SCRIPT T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Detects cloaked Mimikatz in VBS obfuscation"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-21 11:42:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "ANOMALY, DEMO, HKTL, OBFUS, S0002, SCRIPT, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "::::::ExecuteGlobal unescape(unescape(" ascii
   condition: 
      filesize < 500KB and all of them
}