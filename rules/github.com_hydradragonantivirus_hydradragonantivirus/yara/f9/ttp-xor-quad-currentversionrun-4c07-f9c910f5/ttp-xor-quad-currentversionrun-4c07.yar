rule TTP_XOR_QUAD_CurrentVersionRun_4c07 {
  strings:
    $key_4c07 = { 1f 68 [2] 3b 66 [2] 10 4a [2] 3e 68 [2] 2a 73 [2] 25 69 [2] 3b 74 [2] 39 75 [2] 22 73 [2] 3e 74 [2] 22 5b }

  condition:
    any of them
}