rule TTP_XOR_QUAD_CurrentVersionRun_5607 {
  strings:
    $key_5607 = { 05 68 [2] 21 66 [2] 0a 4a [2] 24 68 [2] 30 73 [2] 3f 69 [2] 21 74 [2] 23 75 [2] 38 73 [2] 24 74 [2] 38 5b }

  condition:
    any of them
}