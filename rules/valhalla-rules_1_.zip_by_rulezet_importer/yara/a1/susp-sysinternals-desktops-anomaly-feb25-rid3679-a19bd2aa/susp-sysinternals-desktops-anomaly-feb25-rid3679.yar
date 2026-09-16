rule SUSP_Sysinternals_Desktops_Anomaly_Feb25_RID3679 : ANOMALY DEMO EXE FILE SUSP {
   meta:
      description = "Detects anomalies in Sysinternals Desktops binaries"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-02-14 16:57:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "ANOMALY, DEMO, EXE, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Software\\Sysinternals\\Desktops" wide fullword
      $s2 = "Sysinternals Desktops" wide fullword
      $s3 = "http://www.sysinternals.com" wide fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize > 350KB and all of them
}