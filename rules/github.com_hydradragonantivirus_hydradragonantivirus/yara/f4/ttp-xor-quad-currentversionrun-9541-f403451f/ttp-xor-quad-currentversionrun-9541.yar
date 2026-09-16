rule TTP_XOR_QUAD_CurrentVersionRun_9541 {
  strings:
    $key_9541 = { c6 2e [2] e2 20 [2] c9 0c [2] e7 2e [2] f3 35 [2] fc 2f [2] e2 32 [2] e0 33 [2] fb 35 [2] e7 32 [2] fb 1d }

  condition:
    any of them
}