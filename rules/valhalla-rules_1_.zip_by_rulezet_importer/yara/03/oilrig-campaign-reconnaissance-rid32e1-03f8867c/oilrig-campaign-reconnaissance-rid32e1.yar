rule OilRig_Campaign_Reconnaissance_RID32E1 : DEMO G0049 MAL MIDDLE_EAST T1016 T1033 T1087_002 {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2016/10/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/"
      date = "2016-10-12 14:24:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "5893eae26df8e15c1e0fa763bf88a1ae79484cdb488ba2fc382700ff2cfab80c"
      tags = "DEMO, G0049, MAL, MIDDLE_EAST, T1016, T1033, T1087_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "whoami & hostname & ipconfig /all" ascii
      $s2 = "net user /domain 2>&1 & net group /domain 2>&1" ascii
      $s3 = "net group \"domain admins\" /domain 2>&1 & " ascii
   condition: 
      ( filesize < 1KB and 1 of them )
}