rule TTP_XOR_QUAD_CurrentVersionRun_76c8 {
  strings:
    $key_76c8 = { 25 a7 [2] 01 a9 [2] 2a 85 [2] 04 a7 [2] 10 bc [2] 1f a6 [2] 01 bb [2] 03 ba [2] 18 bc [2] 04 bb [2] 18 94 }

  condition:
    any of them
}