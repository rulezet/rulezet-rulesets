rule BadRabbit_Mimikatz_Comp_RID2FFF : DEMO EXE FILE MAL S0002 T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://pastebin.com/Y7pJv3tK"
      date = "2017-10-25 12:21:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2f8c54f9fa8e47596a3beff0031f85360e56840c77f71c6a573ace6f46412035"
      tags = "DEMO, EXE, FILE, MAL, S0002, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%lS%lS%lS:%lS" fullword wide
      $s2 = "lsasrv" fullword wide
      $s3 = "CredentialKeys" ascii
      $s4 = { 50 72 69 6D 61 72 79 00 6D 00 73 00 76 00 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 3 of them )
}