rule TTP_XOR_QUAD_CurrentVersionRun_7707 {
  strings:
    $key_7707 = { 24 68 [2] 00 66 [2] 2b 4a [2] 05 68 [2] 11 73 [2] 1e 69 [2] 00 74 [2] 02 75 [2] 19 73 [2] 05 74 [2] 19 5b }

  condition:
    any of them
}