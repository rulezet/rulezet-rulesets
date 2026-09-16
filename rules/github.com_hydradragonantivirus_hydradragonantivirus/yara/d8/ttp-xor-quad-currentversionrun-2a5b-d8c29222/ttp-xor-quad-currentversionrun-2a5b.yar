rule TTP_XOR_QUAD_CurrentVersionRun_2a5b {
  strings:
    $key_2a5b = { 79 34 [2] 5d 3a [2] 76 16 [2] 58 34 [2] 4c 2f [2] 43 35 [2] 5d 28 [2] 5f 29 [2] 44 2f [2] 58 28 [2] 44 07 }

  condition:
    any of them
}