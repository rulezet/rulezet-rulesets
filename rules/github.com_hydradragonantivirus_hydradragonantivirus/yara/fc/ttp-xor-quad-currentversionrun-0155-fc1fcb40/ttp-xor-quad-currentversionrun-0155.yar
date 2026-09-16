rule TTP_XOR_QUAD_CurrentVersionRun_0155 {
  strings:
    $key_0155 = { 52 3a [2] 76 34 [2] 5d 18 [2] 73 3a [2] 67 21 [2] 68 3b [2] 76 26 [2] 74 27 [2] 6f 21 [2] 73 26 [2] 6f 09 }

  condition:
    any of them
}