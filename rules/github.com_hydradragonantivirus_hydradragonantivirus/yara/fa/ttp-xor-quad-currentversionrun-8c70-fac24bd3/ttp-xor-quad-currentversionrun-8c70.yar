rule TTP_XOR_QUAD_CurrentVersionRun_8c70 {
  strings:
    $key_8c70 = { df 1f [2] fb 11 [2] d0 3d [2] fe 1f [2] ea 04 [2] e5 1e [2] fb 03 [2] f9 02 [2] e2 04 [2] fe 03 [2] e2 2c }

  condition:
    any of them
}