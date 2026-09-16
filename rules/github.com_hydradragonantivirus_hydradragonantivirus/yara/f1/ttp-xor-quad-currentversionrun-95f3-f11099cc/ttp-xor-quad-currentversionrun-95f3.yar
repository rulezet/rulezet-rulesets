rule TTP_XOR_QUAD_CurrentVersionRun_95f3 {
  strings:
    $key_95f3 = { c6 9c [2] e2 92 [2] c9 be [2] e7 9c [2] f3 87 [2] fc 9d [2] e2 80 [2] e0 81 [2] fb 87 [2] e7 80 [2] fb af }

  condition:
    any of them
}