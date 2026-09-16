rule TTP_XOR_QUAD_CurrentVersionRun_7104 {
  strings:
    $key_7104 = { 22 6b [2] 06 65 [2] 2d 49 [2] 03 6b [2] 17 70 [2] 18 6a [2] 06 77 [2] 04 76 [2] 1f 70 [2] 03 77 [2] 1f 58 }

  condition:
    any of them
}