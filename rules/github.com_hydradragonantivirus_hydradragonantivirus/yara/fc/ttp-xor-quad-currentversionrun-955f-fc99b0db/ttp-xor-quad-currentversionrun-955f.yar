rule TTP_XOR_QUAD_CurrentVersionRun_955f {
  strings:
    $key_955f = { c6 30 [2] e2 3e [2] c9 12 [2] e7 30 [2] f3 2b [2] fc 31 [2] e2 2c [2] e0 2d [2] fb 2b [2] e7 2c [2] fb 03 }

  condition:
    any of them
}