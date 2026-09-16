rule TTP_XOR_QUAD_CurrentVersionRun_8c2c {
  strings:
    $key_8c2c = { df 43 [2] fb 4d [2] d0 61 [2] fe 43 [2] ea 58 [2] e5 42 [2] fb 5f [2] f9 5e [2] e2 58 [2] fe 5f [2] e2 70 }

  condition:
    any of them
}