rule TTP_XOR_QUAD_CurrentVersionRun_954a {
  strings:
    $key_954a = { c6 25 [2] e2 2b [2] c9 07 [2] e7 25 [2] f3 3e [2] fc 24 [2] e2 39 [2] e0 38 [2] fb 3e [2] e7 39 [2] fb 16 }

  condition:
    any of them
}