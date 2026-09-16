rule APT_Thrip_Sample_Jun18_10_RID2FD2 : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:13:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "350d2a6f8e6a4969ffbf75d9f9aae99e7b3a8cd8708fd66f977e07d7fbf842e3"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "!This Program cannot be run in DOS mode." fullword ascii
      $x2 = "!this program cannot be run in dos mode." fullword ascii
      $s1 = "svchost.dll" fullword ascii
      $s2 = "constructor or from DllMain." fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( $x1 or 2 of them )
}