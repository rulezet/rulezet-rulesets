rule TTP_XOR_QUAD_CurrentVersionRun_950c {
  strings:
    $key_950c = { c6 63 [2] e2 6d [2] c9 41 [2] e7 63 [2] f3 78 [2] fc 62 [2] e2 7f [2] e0 7e [2] fb 78 [2] e7 7f [2] fb 50 }

  condition:
    any of them
}