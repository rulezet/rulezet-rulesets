rule TTP_XOR_QUAD_CurrentVersionRun_957a {
  strings:
    $key_957a = { c6 15 [2] e2 1b [2] c9 37 [2] e7 15 [2] f3 0e [2] fc 14 [2] e2 09 [2] e0 08 [2] fb 0e [2] e7 09 [2] fb 26 }

  condition:
    any of them
}