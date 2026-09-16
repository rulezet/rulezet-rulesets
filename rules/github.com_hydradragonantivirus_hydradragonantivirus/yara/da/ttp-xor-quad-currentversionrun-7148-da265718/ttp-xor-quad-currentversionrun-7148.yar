rule TTP_XOR_QUAD_CurrentVersionRun_7148 {
  strings:
    $key_7148 = { 22 27 [2] 06 29 [2] 2d 05 [2] 03 27 [2] 17 3c [2] 18 26 [2] 06 3b [2] 04 3a [2] 1f 3c [2] 03 3b [2] 1f 14 }

  condition:
    any of them
}