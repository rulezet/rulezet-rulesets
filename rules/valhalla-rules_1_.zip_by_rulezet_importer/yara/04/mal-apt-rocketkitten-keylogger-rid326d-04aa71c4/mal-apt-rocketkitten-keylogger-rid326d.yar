rule MAL_APT_RocketKitten_Keylogger_RID326D : APT DEMO EXE FILE G0130 MAL MIDDLE_EAST T1056_001 {
   meta:
      description = "Detects Keylogger used in Rocket Kitten APT"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/vinfo/us/security/news/cyber-attacks/rocket-kitten-continues-attacks-on-middle-east-targets"
      date = "2015-09-01 14:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "1c9e519dca0468a87322bebe2a06741136de7969a4eb3efda0ab8db83f0807b4"
      hash2 = "495a15f9f30d6f6096a97c2bd8cc5edd4d78569b8d541b1d5a64169f8109bc5b"
      hash3 = "5dcc91911ea6c80508a2785ea94cce1f1a41b6362b094552e8494d655ea04e72"
      tags = "APT, DEMO, EXE, FILE, G0130, MAL, MIDDLE_EAST, T1056_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\CWoolger.pdb" ascii
      $x2 = "WoolenLoger\\obj\\x86\\Release" ascii
      $x3 = "D:\\Yaser Logers\\" 
      $z1 = "woolger" fullword wide
      $s1 = "oShellLink.TargetPath = \"" fullword ascii
      $s2 = "wscript.exe " fullword ascii
      $s3 = "strSTUP = WshShell.SpecialFolders(\"Startup\")" fullword ascii
      $s4 = "[CapsLock]" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) or ( $z1 and 2 of ( $s* ) ) ) ) or ( $z1 and all of ( $s* ) )
}