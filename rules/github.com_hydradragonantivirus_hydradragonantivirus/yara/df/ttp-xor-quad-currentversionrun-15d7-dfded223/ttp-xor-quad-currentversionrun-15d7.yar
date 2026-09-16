rule TTP_XOR_QUAD_CurrentVersionRun_15d7 {
  strings:
    $key_15d7 = { 46 b8 [2] 62 b6 [2] 49 9a [2] 67 b8 [2] 73 a3 [2] 7c b9 [2] 62 a4 [2] 60 a5 [2] 7b a3 [2] 67 a4 [2] 7b 8b }

  condition:
    any of them
}