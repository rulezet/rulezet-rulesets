rule TTP_XOR_QUAD_CurrentVersionRun_0c75 {
  strings:
    $key_0c75 = { 5f 1a [2] 7b 14 [2] 50 38 [2] 7e 1a [2] 6a 01 [2] 65 1b [2] 7b 06 [2] 79 07 [2] 62 01 [2] 7e 06 [2] 62 29 }

  condition:
    any of them
}