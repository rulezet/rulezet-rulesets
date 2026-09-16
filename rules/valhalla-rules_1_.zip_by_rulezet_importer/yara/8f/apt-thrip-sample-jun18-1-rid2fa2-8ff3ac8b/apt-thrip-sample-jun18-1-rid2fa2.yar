rule APT_Thrip_Sample_Jun18_1_RID2FA2 : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:05:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "59509a17d516813350fe1683ca6b9727bd96dd81ce3435484a5a53b472ff4ae9"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "idocback.dll" fullword ascii
      $s2 = "constructor or from DllMain." fullword ascii
      $s3 = "appmgmt" fullword ascii
      $s4 = "chksrv" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}