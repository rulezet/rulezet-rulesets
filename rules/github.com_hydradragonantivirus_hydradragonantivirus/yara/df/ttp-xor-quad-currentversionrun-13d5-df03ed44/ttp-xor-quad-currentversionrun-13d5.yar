rule TTP_XOR_QUAD_CurrentVersionRun_13d5 {
  strings:
    $key_13d5 = { 40 ba [2] 64 b4 [2] 4f 98 [2] 61 ba [2] 75 a1 [2] 7a bb [2] 64 a6 [2] 66 a7 [2] 7d a1 [2] 61 a6 [2] 7d 89 }

  condition:
    any of them
}