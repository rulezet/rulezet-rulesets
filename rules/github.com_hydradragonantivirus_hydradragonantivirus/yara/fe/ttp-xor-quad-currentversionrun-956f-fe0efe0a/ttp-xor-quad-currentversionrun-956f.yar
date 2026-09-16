rule TTP_XOR_QUAD_CurrentVersionRun_956f {
  strings:
    $key_956f = { c6 00 [2] e2 0e [2] c9 22 [2] e7 00 [2] f3 1b [2] fc 01 [2] e2 1c [2] e0 1d [2] fb 1b [2] e7 1c [2] fb 33 }

  condition:
    any of them
}