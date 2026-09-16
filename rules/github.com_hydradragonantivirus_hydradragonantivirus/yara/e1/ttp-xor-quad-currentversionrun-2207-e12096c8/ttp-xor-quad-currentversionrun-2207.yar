rule TTP_XOR_QUAD_CurrentVersionRun_2207 {
  strings:
    $key_2207 = { 71 68 [2] 55 66 [2] 7e 4a [2] 50 68 [2] 44 73 [2] 4b 69 [2] 55 74 [2] 57 75 [2] 4c 73 [2] 50 74 [2] 4c 5b }

  condition:
    any of them
}