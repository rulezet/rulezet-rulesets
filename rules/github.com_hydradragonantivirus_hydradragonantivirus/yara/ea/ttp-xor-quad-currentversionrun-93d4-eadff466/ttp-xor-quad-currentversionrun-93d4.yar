rule TTP_XOR_QUAD_CurrentVersionRun_93d4 {
  strings:
    $key_93d4 = { c0 bb [2] e4 b5 [2] cf 99 [2] e1 bb [2] f5 a0 [2] fa ba [2] e4 a7 [2] e6 a6 [2] fd a0 [2] e1 a7 [2] fd 88 }

  condition:
    any of them
}