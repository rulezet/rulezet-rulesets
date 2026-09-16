rule TTP_XOR_QUAD_CurrentVersionRun_9510 {
  strings:
    $key_9510 = { c6 7f [2] e2 71 [2] c9 5d [2] e7 7f [2] f3 64 [2] fc 7e [2] e2 63 [2] e0 62 [2] fb 64 [2] e7 63 [2] fb 4c }

  condition:
    any of them
}