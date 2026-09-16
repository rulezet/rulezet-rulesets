rule TTP_XOR_QUAD_CurrentVersionRun_9521 {
  strings:
    $key_9521 = { c6 4e [2] e2 40 [2] c9 6c [2] e7 4e [2] f3 55 [2] fc 4f [2] e2 52 [2] e0 53 [2] fb 55 [2] e7 52 [2] fb 7d }

  condition:
    any of them
}