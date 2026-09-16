rule MAL_Winnti_Sample_May18_1_RID3003 : APT CHINA DEMO EXE FILE G0044 GEN MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report - Generic Winnti Rule"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 12:21:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "528d9eaaac67716e6b37dd562770190318c8766fa1b2f33c0974f7d5f6725d41"
      tags = "APT, CHINA, DEMO, EXE, FILE, G0044, GEN, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wireshark" fullword wide
      $s2 = "procexp" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}