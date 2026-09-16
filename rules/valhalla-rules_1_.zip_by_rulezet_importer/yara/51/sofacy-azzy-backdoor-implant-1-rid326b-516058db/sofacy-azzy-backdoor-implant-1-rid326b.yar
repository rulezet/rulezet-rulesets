rule Sofacy_AZZY_Backdoor_Implant_1_RID326B : APT DEMO EXE FILE G0007 RUSSIA {
   meta:
      description = "AZZY Backdoor Implant 4.3 - Sample 1"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
      date = "2015-12-04 14:04:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, G0007, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\tf394kv.dll" wide
      $s2 = "DWN_DLL_MAIN.dll" fullword ascii
      $s3 = "?SendDataToServer_2@@YGHPAEKEPAPAEPAK@Z" ascii
      $s4 = "?Applicate@@YGHXZ" ascii
      $s5 = "?k@@YGPAUHINSTANCE__@@PBD@Z" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 2 of them
}