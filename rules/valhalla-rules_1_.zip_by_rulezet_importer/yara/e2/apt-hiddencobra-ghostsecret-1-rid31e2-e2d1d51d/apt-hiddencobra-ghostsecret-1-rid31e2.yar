rule APT_HiddenCobra_GhostSecret_1_RID31E2 : APT DEMO EXE FILE G0032 NK {
   meta:
      description = "Detects Hidden Cobra Sample"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
      date = "2018-08-11 13:41:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "05a567fe3f7c22a0ef78cc39dcf2d9ff283580c82bdbe880af9549e7014becfc"
      tags = "APT, DEMO, EXE, FILE, G0032, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%s\\%s.dll" fullword wide
      $s2 = "PROXY_SVC_DLL.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}