rule TTP_XOR_QUAD_CurrentVersionRun_5207 {
  strings:
    $key_5207 = { 01 68 [2] 25 66 [2] 0e 4a [2] 20 68 [2] 34 73 [2] 3b 69 [2] 25 74 [2] 27 75 [2] 3c 73 [2] 20 74 [2] 3c 5b }

  condition:
    any of them
}