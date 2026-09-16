rule APT_MAL_RANSOM_ViceSociety_Chily_Jan23_1_RID34E9 : APT DEMO EXE MAL RANSOM {
   meta:
      description = "Detects Chily or SunnyDay malware used by Vice Society"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development/"
      date = "2023-01-12 15:50:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4dabb914b8a29506e1eced1d0467c34107767f10fdefa08c40112b2e6fc32e41"
      tags = "APT, DEMO, EXE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ".[Chily@Dr.Com]" ascii fullword
      $s1 = "localbitcoins.com/buy_bitcoins'>https://localbitcoins.com/buy_bitcoins</a>" ascii fullword
      $s2 = "C:\\Users\\root\\Desktop" ascii fullword
      $s3 = "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"" wide fullword
      $s4 = "cd %userprofile%\\documents\\" wide
      $s5 = "noise.bmp" wide fullword
      $s6 = " Execution time: %fms (1sec=1000ms)" ascii fullword
      $s7 = "/c vssadmin.exe Delete Shadows /All /Quiet" wide fullword
      $op1 = { 4c 89 c5 89 ce 89 0d f5 41 02 00 4c 89 cf 44 8d 04 49 0f af f2 89 15 e9 41 02 00 44 89 c0 } 
      $op2 = { 48 8b 03 48 89 d9 ff 50 10 84 c0 0f 94 c0 01 c0 48 83 c4 20 5b } 
      $op3 = { 31 c0 47 8d 2c 00 45 85 f6 4d 63 ed 0f 8e ec 00 00 00 0f 1f 80 00 00 00 00 0f b7 94 44 40 0c 00 00 83 c1 01 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( 1 of ( $x* ) or 3 of them ) or 4 of them
}