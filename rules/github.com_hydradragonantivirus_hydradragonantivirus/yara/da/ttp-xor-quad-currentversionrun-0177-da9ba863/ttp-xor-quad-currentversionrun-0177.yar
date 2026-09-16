rule TTP_XOR_QUAD_CurrentVersionRun_0177 {
  strings:
    $key_0177 = { 52 18 [2] 76 16 [2] 5d 3a [2] 73 18 [2] 67 03 [2] 68 19 [2] 76 04 [2] 74 05 [2] 6f 03 [2] 73 04 [2] 6f 2b }

  condition:
    any of them
}