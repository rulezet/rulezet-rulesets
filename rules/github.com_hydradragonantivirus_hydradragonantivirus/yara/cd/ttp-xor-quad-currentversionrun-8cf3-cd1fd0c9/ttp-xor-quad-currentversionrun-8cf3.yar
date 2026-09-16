rule TTP_XOR_QUAD_CurrentVersionRun_8cf3 {
  strings:
    $key_8cf3 = { df 9c [2] fb 92 [2] d0 be [2] fe 9c [2] ea 87 [2] e5 9d [2] fb 80 [2] f9 81 [2] e2 87 [2] fe 80 [2] e2 af }

  condition:
    any of them
}