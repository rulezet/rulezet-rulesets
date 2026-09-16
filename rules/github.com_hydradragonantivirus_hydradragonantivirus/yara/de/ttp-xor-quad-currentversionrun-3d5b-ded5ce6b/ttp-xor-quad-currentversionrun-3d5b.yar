rule TTP_XOR_QUAD_CurrentVersionRun_3d5b {
  strings:
    $key_3d5b = { 6e 34 [2] 4a 3a [2] 61 16 [2] 4f 34 [2] 5b 2f [2] 54 35 [2] 4a 28 [2] 48 29 [2] 53 2f [2] 4f 28 [2] 53 07 }

  condition:
    any of them
}