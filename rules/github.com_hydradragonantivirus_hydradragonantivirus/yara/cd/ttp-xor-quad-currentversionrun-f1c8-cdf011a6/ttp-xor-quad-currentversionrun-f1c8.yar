rule TTP_XOR_QUAD_CurrentVersionRun_f1c8 {
  strings:
    $key_f1c8 = { a2 a7 [2] 86 a9 [2] ad 85 [2] 83 a7 [2] 97 bc [2] 98 a6 [2] 86 bb [2] 84 ba [2] 9f bc [2] 83 bb [2] 9f 94 }

  condition:
    any of them
}