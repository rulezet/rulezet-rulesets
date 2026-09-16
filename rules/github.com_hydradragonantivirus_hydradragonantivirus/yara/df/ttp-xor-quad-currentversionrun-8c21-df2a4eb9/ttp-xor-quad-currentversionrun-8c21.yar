rule TTP_XOR_QUAD_CurrentVersionRun_8c21 {
  strings:
    $key_8c21 = { df 4e [2] fb 40 [2] d0 6c [2] fe 4e [2] ea 55 [2] e5 4f [2] fb 52 [2] f9 53 [2] e2 55 [2] fe 52 [2] e2 7d }

  condition:
    any of them
}