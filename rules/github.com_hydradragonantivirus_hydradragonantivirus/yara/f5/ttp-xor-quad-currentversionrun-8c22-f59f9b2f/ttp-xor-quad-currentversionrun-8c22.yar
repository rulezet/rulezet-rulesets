rule TTP_XOR_QUAD_CurrentVersionRun_8c22 {
  strings:
    $key_8c22 = { df 4d [2] fb 43 [2] d0 6f [2] fe 4d [2] ea 56 [2] e5 4c [2] fb 51 [2] f9 50 [2] e2 56 [2] fe 51 [2] e2 7e }

  condition:
    any of them
}