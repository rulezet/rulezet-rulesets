rule FeliksPack3___Scanners_ipscan {
   meta:
      description = "Auto-generated rule on file ipscan.exe"
      author = "yarGen Yara Rule Generator by Florian Roth"
      hash = "6c1bcf0b1297689c8c4c12cc70996a75"
      id = "8360b268-3434-5142-9248-40b7a1589be9"
   strings:
      $s2 = "WCAP;}ECTED"
      $s4 = "NotSupported"
      $s6 = "SCAN.VERSION{_"
   condition:
      all of them
}