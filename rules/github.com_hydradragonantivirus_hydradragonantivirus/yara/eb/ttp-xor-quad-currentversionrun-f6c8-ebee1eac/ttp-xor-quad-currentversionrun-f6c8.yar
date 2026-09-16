rule TTP_XOR_QUAD_CurrentVersionRun_f6c8 {
  strings:
    $key_f6c8 = { a5 a7 [2] 81 a9 [2] aa 85 [2] 84 a7 [2] 90 bc [2] 9f a6 [2] 81 bb [2] 83 ba [2] 98 bc [2] 84 bb [2] 98 94 }

  condition:
    any of them
}