rule TTP_XOR_QUAD_CurrentVersionRun_950b {
  strings:
    $key_950b = { c6 64 [2] e2 6a [2] c9 46 [2] e7 64 [2] f3 7f [2] fc 65 [2] e2 78 [2] e0 79 [2] fb 7f [2] e7 78 [2] fb 57 }

  condition:
    any of them
}