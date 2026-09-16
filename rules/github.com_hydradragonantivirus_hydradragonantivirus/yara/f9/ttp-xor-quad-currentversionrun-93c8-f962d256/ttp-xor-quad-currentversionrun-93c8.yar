rule TTP_XOR_QUAD_CurrentVersionRun_93c8 {
  strings:
    $key_93c8 = { c0 a7 [2] e4 a9 [2] cf 85 [2] e1 a7 [2] f5 bc [2] fa a6 [2] e4 bb [2] e6 ba [2] fd bc [2] e1 bb [2] fd 94 }

  condition:
    any of them
}