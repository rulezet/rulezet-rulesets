rule TTP_XOR_QUAD_CurrentVersionRun_0107 {
  strings:
    $key_0107 = { 52 68 [2] 76 66 [2] 5d 4a [2] 73 68 [2] 67 73 [2] 68 69 [2] 76 74 [2] 74 75 [2] 6f 73 [2] 73 74 [2] 6f 5b }

  condition:
    any of them
}