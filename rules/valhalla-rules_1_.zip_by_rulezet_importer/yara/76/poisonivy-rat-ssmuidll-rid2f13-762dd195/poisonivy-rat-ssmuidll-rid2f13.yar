rule PoisonIvy_RAT_ssMUIDLL_RID2F13 : APT DEMO EXE FILE {
   meta:
      description = "Detects PoisonIvy RAT DLL mentioned in Palo Alto Blog in April 2016"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2016/04/unit42-new-poison-ivy-rat-variant-targets-hong-kong-pro-democracy-activists/"
      date = "2016-04-22 11:41:41"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "7a424ad3f3106b87e8e82c7125834d7d8af8730a2a97485a639928f66d5f6bf4"
      hash2 = "6eb7657603edb2b75ed01c004d88087abe24df9527b272605b8517a423557fe6"
      hash3 = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ssMUIDLL.dll" fullword ascii
      $op1 = { 6a 00 c6 07 e9 ff d6 } 
      $op2 = { 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 } 
      $op3 = { 6a 00 88 7f 02 ff d6 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 20KB and ( all of ( $op* ) ) ) or ( all of them )
}