rule MAL_RANSOM_LNX_macOS_LockBit_Apr23_1_RID331B : CRIME DEMO LINUX LockBit MACOS MAL RANSOM {
   meta:
      description = "Detects LockBit ransomware samples for Linux and macOS"
      author = "Florian Roth"
      reference = "https://twitter.com/malwrhunterteam/status/1647384505550876675?s=20"
      date = "2023-04-15 14:33:41"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0a2bffa0a30ec609d80591eef1d0994d8b37ab1f6a6bad7260d9d435067fb48e"
      hash2 = "9ebcbaf3c9e2bbce6b2331238ab584f95f7ced326ca4aba2ddcc8aa8ee964f66"
      hash3 = "a405d034c01a357a89c9988ffe8a46a165915df18fd297469b2bcaaf97578442"
      tags = "CRIME, DEMO, LINUX, LockBit, MACOS, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "restore-my-files.txt" ascii fullword
      $s1 = "ntuser.dat.log" ascii fullword
      $s2 = "bootsect.bak" ascii fullword
      $s3 = "autorun.inf" ascii fullword
      $s4 = "lockbit" ascii fullword
      $xc1 = { 33 38 36 00 63 6D 64 00 61 6E 69 00 61 64 76 00 6D 73 69 00 6D 73 70 00 63 6F 6D 00 6E 6C 73 } 
      $xc2 = { 6E 74 6C 64 72 00 6E 74 75 73 65 72 2E 64 61 74 2E 6C 6F 67 00 62 6F 6F 74 73 65 63 74 2E 62 61 6B } 
      $xc3 = { 76 6D 2E 73 74 61 74 73 2E 76 6D 2E 76 5F 66 72 65 65 5F 63 6F 75 6E 74 00 61 2B 00 2F 2A } 
      $op1 = { 84 e5 f0 00 f0 e7 10 40 2d e9 2e 10 a0 e3 00 40 a0 e1 ?? fe ff } 
      $op2 = { 00 90 a0 e3 40 20 58 e2 3f 80 08 e2 3f 30 c2 e3 09 20 98 e1 08 20 9d } 
      $op3 = { 2d e9 01 70 43 e2 07 00 13 e1 01 60 a0 e1 08 d0 4d e2 02 40 } 
   condition: 
      ( uint32be ( 0 ) == 0x7f454c46 or uint16 ( 0 ) == 0xfeca or uint16 ( 0 ) == 0xfacf or uint32 ( 0 ) == 0xbebafeca ) and ( 1 of ( $x* ) or 3 of them ) or 2 of ( $x* ) or 5 of them
}