rule Shamoon2_Wiper {
   meta:
      description = "Detects Shamoon 2.0 Wiper Component"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 70
      hash1 = "c7fc1f9c2bed748b50a599ee2fa609eb7c9ddaeb9cd16633ba0d10cf66891d8a"
      hash2 = "128fa5815c6fee68463b18051c1a1ccdf28c599ce321691686b1efa4838a2acd"
      id = "6660a64c-daa4-59e6-aa65-55194cac600c"
   strings:
      $a1 = "\\??\\%s\\System32\\%s.exe" fullword wide
      $x1 = "IWHBWWHVCIDBRAFUASIIWURRTWRTIBIVJDGWTRRREFDEAEBIAEBJGGCSVUHGVJUHADIEWAFGWADRUWDTJBHTSITDVVBCIDCWHRHVTDVCDESTHWSUAEHGTWTJWFIRTBRB" wide
      $s1 = "UFWYNYNTS" fullword wide
      $s2 = "\\\\?\\ElRawDisk" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 3 of them )
}