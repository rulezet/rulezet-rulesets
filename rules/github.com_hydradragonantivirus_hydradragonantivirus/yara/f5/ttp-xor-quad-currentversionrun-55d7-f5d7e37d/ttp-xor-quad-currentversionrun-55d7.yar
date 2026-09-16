rule TTP_XOR_QUAD_CurrentVersionRun_55d7 {
  strings:
    $key_55d7 = { 06 b8 [2] 22 b6 [2] 09 9a [2] 27 b8 [2] 33 a3 [2] 3c b9 [2] 22 a4 [2] 20 a5 [2] 3b a3 [2] 27 a4 [2] 3b 8b }

  condition:
    any of them
}