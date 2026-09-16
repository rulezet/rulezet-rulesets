rule TTP_XOR_QUAD_CurrentVersionRun_e4c8 {
  strings:
    $key_e4c8 = { b7 a7 [2] 93 a9 [2] b8 85 [2] 96 a7 [2] 82 bc [2] 8d a6 [2] 93 bb [2] 91 ba [2] 8a bc [2] 96 bb [2] 8a 94 }

  condition:
    any of them
}