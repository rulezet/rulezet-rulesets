rule TTP_XOR_QUAD_CurrentVersionRun_96d4 {
  strings:
    $key_96d4 = { c5 bb [2] e1 b5 [2] ca 99 [2] e4 bb [2] f0 a0 [2] ff ba [2] e1 a7 [2] e3 a6 [2] f8 a0 [2] e4 a7 [2] f8 88 }

  condition:
    any of them
}