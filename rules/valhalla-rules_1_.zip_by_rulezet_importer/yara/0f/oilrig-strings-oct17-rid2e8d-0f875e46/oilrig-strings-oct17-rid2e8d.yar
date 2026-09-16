rule OilRig_Strings_Oct17_RID2E8D : APT DEMO G0049 MIDDLE_EAST {
   meta:
      description = "Detects strings from OilRig malware and malicious scripts"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/"
      date = "2017-10-18 11:19:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      tags = "APT, DEMO, G0049, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "%localappdata%\\srvHealth.exe" fullword wide ascii
      $x2 = "%localappdata%\\srvBS.txt" fullword wide ascii
      $x3 = "Agent Injector\\PolicyConverter\\Inner\\obj\\Release\\Inner.pdb" ascii
      $x4 = "Agent Injector\\PolicyConverter\\Joiner\\obj\\Release\\Joiner.pdb" ascii
      $s3 = ".LoadDll(\"Run\", arg, \"C:\\\\Windows\\\\" ascii
   condition: 
      filesize < 800KB and 1 of them
}