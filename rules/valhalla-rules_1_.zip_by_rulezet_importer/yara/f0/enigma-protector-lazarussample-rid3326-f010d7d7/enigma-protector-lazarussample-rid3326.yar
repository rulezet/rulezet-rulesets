rule Enigma_Protector_LazarusSample_RID3326 : APT DEMO EXE FILE T1027_002 {
   meta:
      description = "Detects malware packed with the Enigma protector"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/sas/77908/lazarus-under-the-hood/"
      date = "2017-04-12 14:35:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d4616f9706403a0d5a2f9a8726230a4693e4c95c58df5c753ccc684f1d3542e2"
      tags = "APT, DEMO, EXE, FILE, T1027_002"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 5d 5d 5d aa bf 5e 95 d6 dc 51 5d 5d 5d 5e 98 0d } 
      $op2 = { 52 d9 47 5d 5d 5d dd a6 b4 52 d9 4c 5d 5d 5d 3b } 
      $op3 = { 9f 59 14 52 d8 a9 a2 a2 a2 00 9f 51 5d d6 d1 79 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}