rule TTP_XOR_QUAD_CurrentVersionRun_950e {
  strings:
    $key_950e = { c6 61 [2] e2 6f [2] c9 43 [2] e7 61 [2] f3 7a [2] fc 60 [2] e2 7d [2] e0 7c [2] fb 7a [2] e7 7d [2] fb 52 }

  condition:
    any of them
}