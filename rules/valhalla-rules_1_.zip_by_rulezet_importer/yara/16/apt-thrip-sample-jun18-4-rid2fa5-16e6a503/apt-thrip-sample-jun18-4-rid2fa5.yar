rule APT_Thrip_Sample_Jun18_4_RID2FA5 : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:06:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6b236d3fc54d36e6dc2a26299f6ded597058fed7c9099f1a37716c5e4b162abc"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\system32\\wbem\\tmf\\caches_version.db" ascii
      $s2 = "ProcessName No Access" fullword ascii
      $s3 = "Hwnd of Process NULL" fullword ascii
      $s4 = "*********The new session is be opening:(%d)**********" fullword ascii
      $s5 = "[EXECUTE]" fullword ascii
      $s6 = "/------------------------------------------------------------------------" fullword ascii
      $s7 = "constructor or from DllMain." fullword ascii
      $s8 = "Time:%d-%d-%d %d:%d:%d" fullword ascii
      $s9 = "\\info.config" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 5 of them
}