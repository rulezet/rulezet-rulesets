rule OilRig_Strings_Oct17 {
   meta:
      description = "Detects strings from OilRig malware and malicious scripts"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/"
      date = "2017-10-18"
      modified = "2022-12-21"
      id = "edf7c7ca-0c58-5507-8d99-83078ff8947a"
   strings:
      $x1 = "%localappdata%\\srvHealth.exe" fullword wide ascii
      $x2 = "%localappdata%\\srvBS.txt" fullword wide ascii
      $x3 = "Agent Injector\\PolicyConverter\\Inner\\obj\\Release\\Inner.pdb" ascii
      $x4 = "Agent Injector\\PolicyConverter\\Joiner\\obj\\Release\\Joiner.pdb" ascii
      $s3 = ".LoadDll(\"Run\", arg, \"C:\\\\Windows\\\\" ascii
   condition:
      filesize < 800KB and 1 of them
}