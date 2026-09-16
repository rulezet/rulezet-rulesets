rule MAL_Etoroloro_Malicious_NodePackage_Dec25 {
   meta:
      description = "Detects malicious component of node package named Etoroloro"
      reference = "Internal Research"
      author = "Pezier Pierre-Henri"
      date = "2025-12-12"
      score = 80
      hash = "f08c5b748c91dd45fd73c5e85920f656e361d94b869e2147410b2b528c6ae78f"
   strings:
      $s1 = "DLLSideload."
      $s2 = "Failed to expand path:" wide
      $op1 = {
         41 0f af c0                    48 8d 52 01                    0f b6 c9                       45 69 c0 35 d4 04 00           03 c1                          0f b6 0a                       84 c9                          75 e5                       }
   condition:
      uint16(0) == 0x5a4d
      and (all of ($s*) or $op1)
}