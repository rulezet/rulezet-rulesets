rule TTP_XOR_QUAD_CurrentVersionRun_92fa {
  strings:
    $key_92fa = { c1 95 [2] e5 9b [2] ce b7 [2] e0 95 [2] f4 8e [2] fb 94 [2] e5 89 [2] e7 88 [2] fc 8e [2] e0 89 [2] fc a6 }

  condition:
    any of them
}