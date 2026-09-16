rule HKTL_PortScanner_Simple_Jan14 {
   meta:
      description = "Auto-generated rule on file PortScanner.exe"
      author = "yarGen Yara Rule Generator by Florian Roth"
      hash = "b381b9212282c0c650cb4b0323436c63"
      old_rule_name = "PortScanner"
      id = "3e8960ce-0428-51e1-b992-4fa09fee8520"
   strings:
      $s0 = "Scan Ports Every"
      $s3 = "Scan All Possible Ports!"
   condition:
      all of them
}