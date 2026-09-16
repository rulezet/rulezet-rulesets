rule TTP_XOR_QUAD_CurrentVersionRun_02d5 {
  strings:
    $key_02d5 = { 51 ba [2] 75 b4 [2] 5e 98 [2] 70 ba [2] 64 a1 [2] 6b bb [2] 75 a6 [2] 77 a7 [2] 6c a1 [2] 70 a6 [2] 6c 89 }

  condition:
    any of them
}