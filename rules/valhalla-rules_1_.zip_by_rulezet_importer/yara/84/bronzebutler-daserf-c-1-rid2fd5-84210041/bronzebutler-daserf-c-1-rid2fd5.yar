import "pe"
rule BronzeButler_Daserf_C_1_RID2FD5 : APT CHINA DEMO EXE FILE G0060 daserf {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      author = "Florian Roth"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14 12:14:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a4afd9df1b4cc014c3a89d7b4a560fa3e368b02286c42841762714b23e68cc05"
      hash2 = "90ac1fb148ded4f46949a5fea4cd8c65d4ea9585046d66459328a5866f8198b2"
      hash3 = "331ac0965b50958db49b7794cc819b2945d7b5e5e919c185d83e997e205f107b"
      tags = "APT, CHINA, DEMO, EXE, FILE, G0060, daserf"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "(c) 2010 DYAMAR EnGineerinG, All rights reserved, http://www.dyamar.com." fullword ascii
      $s2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1)" fullword ascii
      $a1 = "ndkkwqgcm" fullword ascii
      $a2 = "RtlGetCo" fullword ascii
      $a3 = "hutils" fullword ascii
      $b1 = "%USERPROFILE%\\System" fullword ascii
      $b2 = "msid.dat" fullword ascii
      $b3 = "DRIVE_REMOTE" fullword wide
      $b4 = "%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
      $b5 = "jcbhe.asp" fullword ascii
      $b6 = "edset.asp" fullword ascii
      $b7 = "bxcve.asp" fullword ascii
      $b8 = "hcvery.php" fullword ascii
      $b9 = "ynhkef.php" fullword ascii
      $b10 = "dkgwey.php" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "088382f4887e3b2c4bd5157f2d72b618" or all of ( $a* ) or 4 of them )
}