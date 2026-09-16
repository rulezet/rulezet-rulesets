rule TTP_XOR_QUAD_CurrentVersionRun_3607 {
  strings:
    $key_3607 = { 65 68 [2] 41 66 [2] 6a 4a [2] 44 68 [2] 50 73 [2] 5f 69 [2] 41 74 [2] 43 75 [2] 58 73 [2] 44 74 [2] 58 5b }

  condition:
    any of them
}