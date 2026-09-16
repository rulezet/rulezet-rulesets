rule TTP_XOR_QUAD_CurrentVersionRun_f2c9 {
  strings:
    $key_f2c9 = { a1 a6 [2] 85 a8 [2] ae 84 [2] 80 a6 [2] 94 bd [2] 9b a7 [2] 85 ba [2] 87 bb [2] 9c bd [2] 80 ba [2] 9c 95 }

  condition:
    any of them
}