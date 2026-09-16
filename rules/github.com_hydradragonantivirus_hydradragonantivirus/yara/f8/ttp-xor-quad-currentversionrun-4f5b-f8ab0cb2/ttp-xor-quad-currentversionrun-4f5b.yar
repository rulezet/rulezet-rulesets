rule TTP_XOR_QUAD_CurrentVersionRun_4f5b {
  strings:
    $key_4f5b = { 1c 34 [2] 38 3a [2] 13 16 [2] 3d 34 [2] 29 2f [2] 26 35 [2] 38 28 [2] 3a 29 [2] 21 2f [2] 3d 28 [2] 21 07 }

  condition:
    any of them
}