rule TTP_XOR_QUAD_CurrentVersionRun_9552 {
  strings:
    $key_9552 = { c6 3d [2] e2 33 [2] c9 1f [2] e7 3d [2] f3 26 [2] fc 3c [2] e2 21 [2] e0 20 [2] fb 26 [2] e7 21 [2] fb 0e }

  condition:
    any of them
}