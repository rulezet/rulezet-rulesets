rule TTP_XOR_QUAD_CurrentVersionRun_95ef {
  strings:
    $key_95ef = { c6 80 [2] e2 8e [2] c9 a2 [2] e7 80 [2] f3 9b [2] fc 81 [2] e2 9c [2] e0 9d [2] fb 9b [2] e7 9c [2] fb b3 }

  condition:
    any of them
}