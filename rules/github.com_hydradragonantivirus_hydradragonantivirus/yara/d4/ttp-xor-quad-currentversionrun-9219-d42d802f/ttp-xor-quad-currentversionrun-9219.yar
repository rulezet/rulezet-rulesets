rule TTP_XOR_QUAD_CurrentVersionRun_9219 {
  strings:
    $key_9219 = { c1 76 [2] e5 78 [2] ce 54 [2] e0 76 [2] f4 6d [2] fb 77 [2] e5 6a [2] e7 6b [2] fc 6d [2] e0 6a [2] fc 45 }

  condition:
    any of them
}