rule TTP_XOR_QUAD_CurrentVersionRun_02d7 {
  strings:
    $key_02d7 = { 51 b8 [2] 75 b6 [2] 5e 9a [2] 70 b8 [2] 64 a3 [2] 6b b9 [2] 75 a4 [2] 77 a5 [2] 6c a3 [2] 70 a4 [2] 6c 8b }

  condition:
    any of them
}