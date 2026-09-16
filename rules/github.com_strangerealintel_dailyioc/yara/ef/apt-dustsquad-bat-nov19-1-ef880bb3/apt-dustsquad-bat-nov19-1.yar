rule APT_DustSquad_BAT_Nov19_1 {
   meta:
      description = "Detection Rule for APT DustSquad campaign Nov19"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
      date = "2019-11-29"
      hash1 = "500983f7e9fb67bbe6651a5780e637474f1cd813600d4ae8b362dcf27d23b3d2"
   strings:
      $x1 = "if exist \"C:\\Users\\admin\\AppData\\Local\\Temp\\62fb5aa21f62e92586829520078c2561.exe\" (" fullword ascii
      $x2 = "del \"C:\\Users\\admin\\AppData\\Local\\Temp\\62fb5aa21f62e92586829520078c2561.exe\"" fullword ascii
      $x3 = "del \"C:\\Users\\admin\\AppData\\Local\\Temp\\s.bat\"" fullword ascii
      $s4 = "ping 192.168.100.84 -n 1 > nul" fullword ascii
      $s5 = "for /L %%n in (1,1,50) do (" fullword ascii
      $s6 = "chcp 1251 > nul" fullword ascii
      $s7 = ") else (" fullword ascii
      $s8 = "62fb5aa21f62e9258682952" ascii
   condition:
      uint16(0) == 0x6863 and filesize < 1KB and
      1 of ($x*) and all of them
}