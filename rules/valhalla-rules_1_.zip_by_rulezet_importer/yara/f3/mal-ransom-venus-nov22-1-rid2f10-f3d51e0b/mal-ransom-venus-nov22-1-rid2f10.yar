import "pe"
rule MAL_RANSOM_Venus_Nov22_1_RID2F10 : CRIME DEMO EXE MAL RANSOM {
   meta:
      description = "Detects Venus Ransomware samples"
      author = "Florian Roth"
      reference = "https://twitter.com/dyngnosis/status/1592588860168421376"
      date = "2022-11-16 11:41:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "46f9cbc3795d6be0edd49a2c43efe6e610b82741755c5076a89eeccaf98ee834"
      hash2 = "6d8e2d8f6aeb0f4512a53fe83b2ef7699513ebaff31735675f46d1beea3a8e05"
      hash3 = "931cab7fbc0eb2bbc5768f8abdcc029cef76aff98540d9f5214786dccdb6a224"
      tags = "CRIME, DEMO, EXE, MAL, RANSOM"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "<html><head><title>Venus</title><style type = \"text" ascii fullword
      $x2 = "xXBLTZKmAu9pjcfxrIK4gkDp/J9XXATjuysFRXG4rH4=" ascii fullword
      $x3 = "%s%x%x%x%x.goodgame" wide fullword
      $s1 = "/c ping localhost -n 3 > nul & del %s" ascii fullword
      $s2 = "C:\\Windows\\%s.png" wide
      $op1 = { 8b 4c 24 24 46 8b 7c 24 14 41 8b 44 24 30 81 c7 00 04 00 00 81 44 24 10 00 04 00 00 40 } 
      $op2 = { 57 c7 45 fc 00 00 00 00 7e 3f 50 33 c0 74 03 9b 6e } 
      $op3 = { 66 89 45 d4 0f 11 45 e8 e8 a8 e7 ff ff 83 c4 14 8d 45 e8 50 8d 45 a4 50 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and ( pe.imphash ( ) == "bb2600e94092da119ee6acbbd047be43" or 1 of ( $x* ) or 2 of them ) or 4 of them
}