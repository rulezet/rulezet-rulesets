import "pe"
rule GoldDragon_Ghost419_RAT_RID2F3A : APT CHINA CRIME DEMO EXE FILE T1082 T1083 {
   meta:
      description = "Detects Ghost419 RAT from Gold Dragon report"
      author = "Florian Roth"
      reference = "https://www.mcafee.com:443/blogs/"
      date = "2018-02-03 11:48:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "45bfa1327c2c0118c152c7192ada429c6d4ae03b8164ebe36ab5ba9a84f5d7aa"
      hash2 = "ee7a9a7589cbbcac8b6bf1a3d9c5d1c1ada98e68ac2f43ff93f768661b7e4a85"
      hash3 = "dee482e5f461a8e531a6a7ea4728535aafdc4941a8939bc3c55f6cb28c46ad3d"
      tags = "APT, CHINA, CRIME, DEMO, EXE, FILE, T1082, T1083"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $x2 = "WebKitFormBoundarywhpFxMBe19cSjFnG" ascii
      $x3 = "\\Microsoft\\HNC\\" ascii
      $x4 = "\\anternet abplorer" ascii
      $x5 = "%s\\abxplore.exe" fullword ascii
      $x6 = "GHOST419" fullword ascii
      $x7 = "I,m Online. %04d - %02d - %02d - %02d - %02d" fullword ascii
      $x8 = "//////////////////////////regkeyenum//////////////" ascii
      $s0 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; .NET CLR 1.1.4322)" fullword ascii
      $s1 = "www.GoldDragon.com" fullword ascii
      $s2 = "/c systeminfo >> %s" fullword ascii
      $s3 = "/c dir %s\\ >> %s" fullword ascii
      $s4 = "DownLoading %02x, %02x, %02x" fullword ascii
      $s5 = "Tran_dll.dll" fullword ascii
      $s6 = "MpCmdRunkr.dll" fullword ascii
      $s7 = "MpCmdRun.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( ( pe.exports ( "ExportFunction" ) and pe.number_of_exports == 1 ) or ( 1 of ( $x* ) and 1 of ( $s* ) ) or 3 of them )
}