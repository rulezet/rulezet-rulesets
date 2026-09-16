rule TTP_XOR_QUAD_CurrentVersionRun_8c1f {
  strings:
    $key_8c1f = { df 70 [2] fb 7e [2] d0 52 [2] fe 70 [2] ea 6b [2] e5 71 [2] fb 6c [2] f9 6d [2] e2 6b [2] fe 6c [2] e2 43 }

  condition:
    any of them
}