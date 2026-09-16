rule TTP_XOR_QUAD_CurrentVersionRun_0c5b {
  strings:
    $key_0c5b = { 5f 34 [2] 7b 3a [2] 50 16 [2] 7e 34 [2] 6a 2f [2] 65 35 [2] 7b 28 [2] 79 29 [2] 62 2f [2] 7e 28 [2] 62 07 }

  condition:
    any of them
}