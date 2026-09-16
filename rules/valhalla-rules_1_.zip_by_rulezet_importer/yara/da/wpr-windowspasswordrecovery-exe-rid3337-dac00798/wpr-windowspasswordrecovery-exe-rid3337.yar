rule WPR_WindowsPasswordRecovery_EXE_RID3337 : DEMO EXE FILE HKTL {
   meta:
      description = "Windows Password Recovery - file wpr.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15 14:38:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c1c64cba5c8e14a1ab8e9dd28828d036581584e66ed111455d6b4737fb807783"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "UuPipe" fullword ascii
      $x2 = "dbadllgl" fullword ascii
      $x3 = "UkVHSVNUUlkgTU9O" fullword ascii
      $x4 = "RklMRSBNT05JVE9SIC0gU1l" fullword ascii
      $s1 = "WPR.exe" fullword wide
      $s2 = "Windows Password Recovery" fullword wide
      $op0 = { 5f df 27 17 89 } 
      $op1 = { 5f 00 00 f2 e5 cb 97 } 
      $op2 = { e8 ed 00 f0 cc e4 00 a0 17 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20000KB and ( 1 of ( $x* ) or all of ( $s* ) or all of ( $op* ) )
}