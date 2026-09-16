rule TTP_XOR_QUAD_CurrentVersionRun_92f1 {
  strings:
    $key_92f1 = { c1 9e [2] e5 90 [2] ce bc [2] e0 9e [2] f4 85 [2] fb 9f [2] e5 82 [2] e7 83 [2] fc 85 [2] e0 82 [2] fc ad }

  condition:
    any of them
}