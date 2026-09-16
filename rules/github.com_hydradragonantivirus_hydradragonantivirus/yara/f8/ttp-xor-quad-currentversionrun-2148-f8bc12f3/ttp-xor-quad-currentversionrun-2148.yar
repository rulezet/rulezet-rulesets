rule TTP_XOR_QUAD_CurrentVersionRun_2148 {
  strings:
    $key_2148 = { 72 27 [2] 56 29 [2] 7d 05 [2] 53 27 [2] 47 3c [2] 48 26 [2] 56 3b [2] 54 3a [2] 4f 3c [2] 53 3b [2] 4f 14 }

  condition:
    any of them
}