rule TTP_XOR_QUAD_CurrentVersionRun_5d07 {
  strings:
    $key_5d07 = { 0e 68 [2] 2a 66 [2] 01 4a [2] 2f 68 [2] 3b 73 [2] 34 69 [2] 2a 74 [2] 28 75 [2] 33 73 [2] 2f 74 [2] 33 5b }

  condition:
    any of them
}