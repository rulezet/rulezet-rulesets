rule TTP_XOR_QUAD_CurrentVersionRun_535b {
  strings:
    $key_535b = { 00 34 [2] 24 3a [2] 0f 16 [2] 21 34 [2] 35 2f [2] 3a 35 [2] 24 28 [2] 26 29 [2] 3d 2f [2] 21 28 [2] 3d 07 }

  condition:
    any of them
}