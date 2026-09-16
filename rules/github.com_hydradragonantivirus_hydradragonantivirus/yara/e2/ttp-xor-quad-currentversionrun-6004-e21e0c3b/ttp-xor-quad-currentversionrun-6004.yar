rule TTP_XOR_QUAD_CurrentVersionRun_6004 {
  strings:
    $key_6004 = { 33 6b [2] 17 65 [2] 3c 49 [2] 12 6b [2] 06 70 [2] 09 6a [2] 17 77 [2] 15 76 [2] 0e 70 [2] 12 77 [2] 0e 58 }

  condition:
    any of them
}