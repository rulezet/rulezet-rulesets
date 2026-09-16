rule TTP_XOR_QUAD_CurrentVersionRun_8ed4 {
  strings:
    $key_8ed4 = { dd bb [2] f9 b5 [2] d2 99 [2] fc bb [2] e8 a0 [2] e7 ba [2] f9 a7 [2] fb a6 [2] e0 a0 [2] fc a7 [2] e0 88 }

  condition:
    any of them
}