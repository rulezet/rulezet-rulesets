rule TTP_XOR_QUAD_CurrentVersionRun_952e {
  strings:
    $key_952e = { c6 41 [2] e2 4f [2] c9 63 [2] e7 41 [2] f3 5a [2] fc 40 [2] e2 5d [2] e0 5c [2] fb 5a [2] e7 5d [2] fb 72 }

  condition:
    any of them
}