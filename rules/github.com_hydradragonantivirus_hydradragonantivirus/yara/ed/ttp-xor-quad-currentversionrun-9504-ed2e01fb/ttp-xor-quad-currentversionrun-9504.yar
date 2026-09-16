rule TTP_XOR_QUAD_CurrentVersionRun_9504 {
  strings:
    $key_9504 = { c6 6b [2] e2 65 [2] c9 49 [2] e7 6b [2] f3 70 [2] fc 6a [2] e2 77 [2] e0 76 [2] fb 70 [2] e7 77 [2] fb 58 }

  condition:
    any of them
}