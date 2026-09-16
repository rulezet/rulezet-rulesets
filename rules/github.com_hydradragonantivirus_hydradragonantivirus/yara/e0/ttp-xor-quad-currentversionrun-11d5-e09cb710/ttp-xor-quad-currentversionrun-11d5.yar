rule TTP_XOR_QUAD_CurrentVersionRun_11d5 {
  strings:
    $key_11d5 = { 42 ba [2] 66 b4 [2] 4d 98 [2] 63 ba [2] 77 a1 [2] 78 bb [2] 66 a6 [2] 64 a7 [2] 7f a1 [2] 63 a6 [2] 7f 89 }

  condition:
    any of them
}