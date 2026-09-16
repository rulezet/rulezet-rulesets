rule TTP_XOR_QUAD_CurrentVersionRun_8c00 {
  strings:
    $key_8c00 = { df 6f [2] fb 61 [2] d0 4d [2] fe 6f [2] ea 74 [2] e5 6e [2] fb 73 [2] f9 72 [2] e2 74 [2] fe 73 [2] e2 5c }

  condition:
    any of them
}