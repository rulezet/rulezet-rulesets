rule Shamoon2_Wiper_RID2C7E : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "Detects Shamoon 2.0 Wiper Component"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2016/11/unit42-shamoon-2-return-disttrack-wiper/"
      date = "2016-12-01 09:51:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "c7fc1f9c2bed748b50a599ee2fa609eb7c9ddaeb9cd16633ba0d10cf66891d8a"
      hash2 = "128fa5815c6fee68463b18051c1a1ccdf28c599ce321691686b1efa4838a2acd"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "\\??\\%s\\System32\\%s.exe" fullword wide
      $x1 = "IWHBWWHVCIDBRAFUASIIWURRTWRTIBIVJDGWTRRREFDEAEBIAEBJGGCSVUHGVJUHADIEWAFGWADRUWDTJBHTSITDVVBCIDCWHRHVTDVCDESTHWSUAEHGTWTJWFIRTBRB" wide
      $s1 = "UFWYNYNTS" fullword wide
      $s2 = "\\\\?\\ElRawDisk" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 3 of them )
}