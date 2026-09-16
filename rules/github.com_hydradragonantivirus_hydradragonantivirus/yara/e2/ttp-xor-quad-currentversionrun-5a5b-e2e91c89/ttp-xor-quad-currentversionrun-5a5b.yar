rule TTP_XOR_QUAD_CurrentVersionRun_5a5b {
  strings:
    $key_5a5b = { 09 34 [2] 2d 3a [2] 06 16 [2] 28 34 [2] 3c 2f [2] 33 35 [2] 2d 28 [2] 2f 29 [2] 34 2f [2] 28 28 [2] 34 07 }

  condition:
    any of them
}