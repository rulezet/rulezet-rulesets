rule TTP_XOR_QUAD_CurrentVersionRun_315b {
  strings:
    $key_315b = { 62 34 [2] 46 3a [2] 6d 16 [2] 43 34 [2] 57 2f [2] 58 35 [2] 46 28 [2] 44 29 [2] 5f 2f [2] 43 28 [2] 5f 07 }

  condition:
    any of them
}