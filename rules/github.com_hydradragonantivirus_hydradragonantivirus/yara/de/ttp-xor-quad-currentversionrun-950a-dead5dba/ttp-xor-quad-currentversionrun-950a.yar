rule TTP_XOR_QUAD_CurrentVersionRun_950a {
  strings:
    $key_950a = { c6 65 [2] e2 6b [2] c9 47 [2] e7 65 [2] f3 7e [2] fc 64 [2] e2 79 [2] e0 78 [2] fb 7e [2] e7 79 [2] fb 56 }

  condition:
    any of them
}