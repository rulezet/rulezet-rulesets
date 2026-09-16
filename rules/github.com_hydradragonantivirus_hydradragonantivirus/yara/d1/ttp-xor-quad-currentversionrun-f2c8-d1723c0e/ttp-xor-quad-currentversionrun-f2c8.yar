rule TTP_XOR_QUAD_CurrentVersionRun_f2c8 {
  strings:
    $key_f2c8 = { a1 a7 [2] 85 a9 [2] ae 85 [2] 80 a7 [2] 94 bc [2] 9b a6 [2] 85 bb [2] 87 ba [2] 9c bc [2] 80 bb [2] 9c 94 }

  condition:
    any of them
}