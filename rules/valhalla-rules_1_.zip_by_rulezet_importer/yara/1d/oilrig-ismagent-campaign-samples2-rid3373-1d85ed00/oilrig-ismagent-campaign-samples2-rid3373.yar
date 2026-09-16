rule OilRig_ISMAgent_Campaign_Samples2_RID3373 : APT DEMO EXE FILE G0049 MIDDLE_EAST T1218_009 {
   meta:
      description = "Detects OilRig malware from Unit 42 report in October 2017"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/"
      date = "2017-10-18 14:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "fcad263d0fe2b418db05f47d4036f0b42aaf201c9b91281dfdcb3201b298e4f4"
      hash2 = "33c187cfd9e3b68c3089c27ac64a519ccc951ccb3c74d75179c520f54f11f647"
      tags = "APT, DEMO, EXE, FILE, G0049, MIDDLE_EAST, T1218_009"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "PolicyConverter.exe" fullword wide
      $x2 = "SrvHealth.exe" fullword wide
      $x3 = "srvBS.txt" fullword wide
      $s1 = "{a3538ba3-5cf7-43f0-bc0e-9b53a98e1643}, PublicKeyToken=3e56350693f7355e" fullword wide
      $s2 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\RegAsm.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and ( 2 of ( $x* ) or 3 of them )
}