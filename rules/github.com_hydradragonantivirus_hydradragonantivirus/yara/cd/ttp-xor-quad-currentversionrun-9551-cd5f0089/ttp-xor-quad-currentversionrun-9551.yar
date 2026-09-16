rule TTP_XOR_QUAD_CurrentVersionRun_9551 {
  strings:
    $key_9551 = { c6 3e [2] e2 30 [2] c9 1c [2] e7 3e [2] f3 25 [2] fc 3f [2] e2 22 [2] e0 23 [2] fb 25 [2] e7 22 [2] fb 0d }

  condition:
    any of them
}