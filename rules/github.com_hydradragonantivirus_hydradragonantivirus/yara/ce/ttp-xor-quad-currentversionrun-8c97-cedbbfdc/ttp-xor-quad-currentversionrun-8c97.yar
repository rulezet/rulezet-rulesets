rule TTP_XOR_QUAD_CurrentVersionRun_8c97 {
  strings:
    $key_8c97 = { df f8 [2] fb f6 [2] d0 da [2] fe f8 [2] ea e3 [2] e5 f9 [2] fb e4 [2] f9 e5 [2] e2 e3 [2] fe e4 [2] e2 cb }

  condition:
    any of them
}