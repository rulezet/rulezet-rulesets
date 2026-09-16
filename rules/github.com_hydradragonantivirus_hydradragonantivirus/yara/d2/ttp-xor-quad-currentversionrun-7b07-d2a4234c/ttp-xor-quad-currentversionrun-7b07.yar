rule TTP_XOR_QUAD_CurrentVersionRun_7b07 {
  strings:
    $key_7b07 = { 28 68 [2] 0c 66 [2] 27 4a [2] 09 68 [2] 1d 73 [2] 12 69 [2] 0c 74 [2] 0e 75 [2] 15 73 [2] 09 74 [2] 15 5b }

  condition:
    any of them
}