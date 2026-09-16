rule TTP_XOR_QUAD_CurrentVersionRun_5a19 {
  strings:
    $key_5a19 = { 09 76 [2] 2d 78 [2] 06 54 [2] 28 76 [2] 3c 6d [2] 33 77 [2] 2d 6a [2] 2f 6b [2] 34 6d [2] 28 6a [2] 34 45 }

  condition:
    any of them
}