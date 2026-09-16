rule Mimikatz_Memory_Rule_1_RID2FB6 : APT DEMO HKTL S0002 T1003 T1134_005 T1550_002 T1550_003 T1569_002 {
   meta:
      description = "Detects password dumper mimikatz in memory (False Positives: an service that could have copied a Mimikatz executable, AV signatures)"
      author = "Florian Roth"
      reference = "-"
      date = "2014-12-22 12:08:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-07-04"
      tags = "APT, DEMO, HKTL, S0002, T1003, T1134_005, T1550_002, T1550_003, T1569_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "sekurlsa::wdigest" fullword ascii
      $s2 = "sekurlsa::logonPasswords" fullword ascii
      $s3 = "sekurlsa::minidump" fullword ascii
      $s4 = "sekurlsa::credman" fullword ascii
      $fp1 = "\"x_mitre_version\": " ascii
      $fp2 = "{\"type\":\"bundle\"," 
      $fp3 = "use strict" ascii fullword
      $fp4 = "\"url\":\"https://attack.mitre.org/" ascii
   condition: 
      1 of ( $s* ) and not 1 of ( $fp* )
}