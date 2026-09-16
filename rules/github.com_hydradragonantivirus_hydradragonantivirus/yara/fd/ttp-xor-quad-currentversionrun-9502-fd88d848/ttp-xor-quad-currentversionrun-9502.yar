rule TTP_XOR_QUAD_CurrentVersionRun_9502 {
  strings:
    $key_9502 = { c6 6d [2] e2 63 [2] c9 4f [2] e7 6d [2] f3 76 [2] fc 6c [2] e2 71 [2] e0 70 [2] fb 76 [2] e7 71 [2] fb 5e }

  condition:
    any of them
}