rule SUSP_Modified_SystemExeFileName_in_File_RID35F8 : DEMO EXE FILE SUSP {
   meta:
      description = "Detecst a variant of a system file name often used by attackers to cloak their activity"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
      date = "2018-12-11 16:35:51"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5723f425e0c55c22c6b8bb74afb6b506943012c33b9ec1c928a71307a8c5889a"
      hash2 = "f1f11830b60e6530b680291509ddd9b5a1e5f425550444ec964a08f5f0c1a44e"
      tags = "DEMO, EXE, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "svchosts.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them
}