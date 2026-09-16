rule TTP_XOR_QUAD_CurrentVersionRun_957c {
  strings:
    $key_957c = { c6 13 [2] e2 1d [2] c9 31 [2] e7 13 [2] f3 08 [2] fc 12 [2] e2 0f [2] e0 0e [2] fb 08 [2] e7 0f [2] fb 20 }

  condition:
    any of them
}