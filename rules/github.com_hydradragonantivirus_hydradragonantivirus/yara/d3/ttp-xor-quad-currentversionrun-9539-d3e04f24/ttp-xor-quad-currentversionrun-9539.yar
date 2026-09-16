rule TTP_XOR_QUAD_CurrentVersionRun_9539 {
  strings:
    $key_9539 = { c6 56 [2] e2 58 [2] c9 74 [2] e7 56 [2] f3 4d [2] fc 57 [2] e2 4a [2] e0 4b [2] fb 4d [2] e7 4a [2] fb 65 }

  condition:
    any of them
}