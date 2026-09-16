rule TTP_XOR_QUAD_CurrentVersionRun_11d4 {
  strings:
    $key_11d4 = { 42 bb [2] 66 b5 [2] 4d 99 [2] 63 bb [2] 77 a0 [2] 78 ba [2] 66 a7 [2] 64 a6 [2] 7f a0 [2] 63 a7 [2] 7f 88 }

  condition:
    any of them
}