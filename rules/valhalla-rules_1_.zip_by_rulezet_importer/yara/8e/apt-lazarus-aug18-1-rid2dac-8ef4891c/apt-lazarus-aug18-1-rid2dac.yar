import "pe"
rule APT_Lazarus_Aug18_1_RID2DAC : APT DEMO EXE FILE G0032 NK {
   meta:
      description = "Detects Lazarus Group Malware"
      author = "Florian Roth"
      reference = "https://securelist.com/operation-applejeus/87553/"
      date = "2018-08-24 10:41:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ef400d73c6920ac811af401259e376458b498eb0084631386136747dfc3dcfa8"
      hash2 = "1b8d3e69fc214cb7a08bef3c00124717f4b4d7fd6be65f2829e9fd337fc7c03c"
      tags = "APT, DEMO, EXE, FILE, G0032, NK"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mws2_32.dll" fullword wide
      $s2 = "%s.bat" fullword wide
      $s3 = "%s%s%s \"%s > %s 2>&1\"" fullword wide
      $s4 = "Microsoft Corporation. All rights reserved." fullword wide
      $s5 = "ping 127.0.0.1 -n 3" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( pe.imphash ( ) == "3af996e4f960108533e69b9033503f40" or 4 of them )
}