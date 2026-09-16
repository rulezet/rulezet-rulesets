rule TTP_XOR_QUAD_CurrentVersionRun_52c9 {
  strings:
    $key_52c9 = { 01 a6 [2] 25 a8 [2] 0e 84 [2] 20 a6 [2] 34 bd [2] 3b a7 [2] 25 ba [2] 27 bb [2] 3c bd [2] 20 ba [2] 3c 95 }

  condition:
    any of them
}