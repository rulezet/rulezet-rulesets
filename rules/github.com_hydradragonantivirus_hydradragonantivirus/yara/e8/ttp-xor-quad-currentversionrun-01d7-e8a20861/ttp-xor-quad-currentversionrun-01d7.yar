rule TTP_XOR_QUAD_CurrentVersionRun_01d7 {
  strings:
    $key_01d7 = { 52 b8 [2] 76 b6 [2] 5d 9a [2] 73 b8 [2] 67 a3 [2] 68 b9 [2] 76 a4 [2] 74 a5 [2] 6f a3 [2] 73 a4 [2] 6f 8b }

  condition:
    any of them
}