rule APT_MAL_ASP_DLL_HAFNIUM_Mar21_1_RID3086 : APT DEMO EXE FILE G0125 MAL {
   meta:
      description = "Detects HAFNIUM compiled ASP.NET DLLs dropped on compromised servers"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-05 12:43:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "097f5f700c000a13b91855beb61a931d34fb0abb738a110368f525e25c5bc738"
      hash2 = "15744e767cbaa9b37ff7bb5c036dda9b653fc54fc9a96fe73fbd639150b3daa3"
      hash3 = "52ae4de2e3f0ef7fe27c699cb60d41129a3acd4a62be60accc85d88c296e1ddb"
      tags = "APT, DEMO, EXE, FILE, G0125, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Page_Load" ascii fullword
      $sc1 = { 20 00 3A 00 20 00 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 (66 | 67) 00 2F 00 00 89 A3 0D 00 0A 00 } 
      $op1 = { 00 43 00 58 00 77 00 30 00 4a 00 45 00 00 51 7e 00 2f } 
      $op2 = { 58 00 77 00 30 00 4a 00 45 00 00 51 7e 00 2f 00 61 00 } 
      $op3 = { 01 0e 0e 05 20 01 01 11 79 04 07 01 12 2d 04 07 01 12 31 02 } 
      $op4 = { 5e 00 03 00 bc 22 00 00 00 00 01 00 85 03 2b 00 03 00 cc } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and all of ( $s* ) or all of ( $op* )
}