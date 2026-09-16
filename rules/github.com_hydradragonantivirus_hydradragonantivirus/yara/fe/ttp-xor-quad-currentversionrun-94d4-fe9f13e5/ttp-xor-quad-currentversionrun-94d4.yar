rule TTP_XOR_QUAD_CurrentVersionRun_94d4 {
  strings:
    $key_94d4 = { c7 bb [2] e3 b5 [2] c8 99 [2] e6 bb [2] f2 a0 [2] fd ba [2] e3 a7 [2] e1 a6 [2] fa a0 [2] e6 a7 [2] fa 88 }

  condition:
    any of them
}