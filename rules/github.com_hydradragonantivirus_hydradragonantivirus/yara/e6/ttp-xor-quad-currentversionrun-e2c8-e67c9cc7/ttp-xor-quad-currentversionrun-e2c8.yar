rule TTP_XOR_QUAD_CurrentVersionRun_e2c8 {
  strings:
    $key_e2c8 = { b1 a7 [2] 95 a9 [2] be 85 [2] 90 a7 [2] 84 bc [2] 8b a6 [2] 95 bb [2] 97 ba [2] 8c bc [2] 90 bb [2] 8c 94 }

  condition:
    any of them
}