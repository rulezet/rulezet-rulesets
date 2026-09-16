rule RottenPotato_Potato_RID2EDA : DEMO EXE FILE HKTL T1053_005 T1068 T1134 {
   meta:
      description = "Detects a component of privilege escalation tool Rotten Potato - file Potato.exe"
      author = "Florian Roth"
      reference = "https://github.com/foxglovesec/RottenPotato"
      date = "2017-02-07 11:32:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "59cdbb21d9e487ca82748168682f1f7af3c5f2b8daee3a09544dd58cbf51b0d5"
      tags = "DEMO, EXE, FILE, HKTL, T1053_005, T1068, T1134"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Potato.exe -ip <ip>" fullword wide
      $x2 = "-enable_httpserver true -enable_spoof true" fullword wide
      $x3 = "/C schtasks.exe /Create /TN omg /TR" fullword wide
      $x4 = "-enable_token true -enable_dce true" fullword wide
      $x5 = "DNS lookup succeeds - UDP Exhaustion failed!" fullword wide
      $x6 = "DNS lookup fails - UDP Exhaustion worked!" fullword wide
      $x7 = "\\obj\\Release\\Potato.pdb" ascii
      $x8 = "function FindProxyForURL(url,host){if (dnsDomainIs(host, \"localhost\")) return \"DIRECT\";" fullword wide
      $s1 = "\"C:\\Windows\\System32\\cmd.exe\" /K start" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of ( $x* ) ) or ( 2 of them )
}