import "pe"
rule OilRig_RGDoor_Gen1_RID2D8D : APT DEMO EXE FILE G0049 MIDDLE_EAST {
   meta:
      description = "Detects RGDoor backdoor used by OilRig group"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/"
      date = "2018-01-27 10:36:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a9c92b29ee05c1522715c7a2f9c543740b60e36373cb47b5620b1f3d8ad96bfa"
      tags = "APT, DEMO, EXE, FILE, G0049, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $c1 = { 00 63 6D 64 24 00 00 00 00 72 00 00 00 00 00 00 00 75 70 6C 6F 61 64 24 } 
      $c2 = { 63 61 6E 27 74 20 6F 70 65 6E 20 66 69 6C 65 3A 20 00 00 00 00 00 00 00 64 6F 77 6E 6C 6F 61 64 24 } 
      $s1 = "MyNativeModule.dll" fullword ascii
      $s2 = "RGSESSIONID=" fullword ascii
      $s3 = "download$" fullword ascii
      $s4 = ".?AVCHelloWorld@@" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "47cb127aad6c7c9954058e61a2a6429a" or 1 of ( $c* ) or 2 of them )
}