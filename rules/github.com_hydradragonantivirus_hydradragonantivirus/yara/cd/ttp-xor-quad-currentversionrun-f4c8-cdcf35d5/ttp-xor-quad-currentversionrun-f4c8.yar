rule TTP_XOR_QUAD_CurrentVersionRun_f4c8 {
  strings:
    $key_f4c8 = { a7 a7 [2] 83 a9 [2] a8 85 [2] 86 a7 [2] 92 bc [2] 9d a6 [2] 83 bb [2] 81 ba [2] 9a bc [2] 86 bb [2] 9a 94 }

  condition:
    any of them
}