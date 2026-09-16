rule TTP_XOR_QUAD_CurrentVersionRun_7907 {
  strings:
    $key_7907 = { 2a 68 [2] 0e 66 [2] 25 4a [2] 0b 68 [2] 1f 73 [2] 10 69 [2] 0e 74 [2] 0c 75 [2] 17 73 [2] 0b 74 [2] 17 5b }

  condition:
    any of them
}