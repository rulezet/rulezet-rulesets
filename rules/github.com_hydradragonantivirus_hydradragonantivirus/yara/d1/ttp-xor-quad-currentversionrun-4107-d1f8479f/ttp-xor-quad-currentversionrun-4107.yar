rule TTP_XOR_QUAD_CurrentVersionRun_4107 {
  strings:
    $key_4107 = { 12 68 [2] 36 66 [2] 1d 4a [2] 33 68 [2] 27 73 [2] 28 69 [2] 36 74 [2] 34 75 [2] 2f 73 [2] 33 74 [2] 2f 5b }

  condition:
    any of them
}