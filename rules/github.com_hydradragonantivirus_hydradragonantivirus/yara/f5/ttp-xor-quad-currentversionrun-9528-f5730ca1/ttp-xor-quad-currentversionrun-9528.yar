rule TTP_XOR_QUAD_CurrentVersionRun_9528 {
  strings:
    $key_9528 = { c6 47 [2] e2 49 [2] c9 65 [2] e7 47 [2] f3 5c [2] fc 46 [2] e2 5b [2] e0 5a [2] fb 5c [2] e7 5b [2] fb 74 }

  condition:
    any of them
}