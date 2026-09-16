rule TTP_XOR_QUAD_CurrentVersionRun_9560 {
  strings:
    $key_9560 = { c6 0f [2] e2 01 [2] c9 2d [2] e7 0f [2] f3 14 [2] fc 0e [2] e2 13 [2] e0 12 [2] fb 14 [2] e7 13 [2] fb 3c }

  condition:
    any of them
}