rule TTP_XOR_QUAD_CurrentVersionRun_37c8 {
  strings:
    $key_37c8 = { 64 a7 [2] 40 a9 [2] 6b 85 [2] 45 a7 [2] 51 bc [2] 5e a6 [2] 40 bb [2] 42 ba [2] 59 bc [2] 45 bb [2] 59 94 }

  condition:
    any of them
}