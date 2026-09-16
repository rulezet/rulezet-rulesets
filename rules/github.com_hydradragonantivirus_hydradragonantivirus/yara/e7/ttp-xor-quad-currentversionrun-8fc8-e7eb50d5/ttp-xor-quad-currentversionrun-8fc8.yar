rule TTP_XOR_QUAD_CurrentVersionRun_8fc8 {
  strings:
    $key_8fc8 = { dc a7 [2] f8 a9 [2] d3 85 [2] fd a7 [2] e9 bc [2] e6 a6 [2] f8 bb [2] fa ba [2] e1 bc [2] fd bb [2] e1 94 }

  condition:
    any of them
}