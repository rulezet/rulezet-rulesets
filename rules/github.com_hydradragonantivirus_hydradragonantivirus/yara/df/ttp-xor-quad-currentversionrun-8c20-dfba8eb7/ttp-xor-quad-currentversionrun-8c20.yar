rule TTP_XOR_QUAD_CurrentVersionRun_8c20 {
  strings:
    $key_8c20 = { df 4f [2] fb 41 [2] d0 6d [2] fe 4f [2] ea 54 [2] e5 4e [2] fb 53 [2] f9 52 [2] e2 54 [2] fe 53 [2] e2 7c }

  condition:
    any of them
}