rule TTP_XOR_QUAD_CurrentVersionRun_13d7 {
  strings:
    $key_13d7 = { 40 b8 [2] 64 b6 [2] 4f 9a [2] 61 b8 [2] 75 a3 [2] 7a b9 [2] 64 a4 [2] 66 a5 [2] 7d a3 [2] 61 a4 [2] 7d 8b }

  condition:
    any of them
}