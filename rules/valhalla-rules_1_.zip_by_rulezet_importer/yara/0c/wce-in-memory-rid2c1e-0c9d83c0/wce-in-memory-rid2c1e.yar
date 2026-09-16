rule WCE_in_memory_RID2C1E : DEMO HKTL T1003 {
   meta:
      description = "Detects Windows Credential Editor (WCE) in memory (and also on disk)"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-08-28 09:35:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wkKUSvflehHr::o:t:s:c:i:d:a:g:" fullword ascii
      $s2 = "wceaux.dll" fullword ascii
   condition: 
      all of them
}