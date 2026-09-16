rule TTP_XOR_QUAD_CurrentVersionRun_955e {
  strings:
    $key_955e = { c6 31 [2] e2 3f [2] c9 13 [2] e7 31 [2] f3 2a [2] fc 30 [2] e2 2d [2] e0 2c [2] fb 2a [2] e7 2d [2] fb 02 }

  condition:
    any of them
}