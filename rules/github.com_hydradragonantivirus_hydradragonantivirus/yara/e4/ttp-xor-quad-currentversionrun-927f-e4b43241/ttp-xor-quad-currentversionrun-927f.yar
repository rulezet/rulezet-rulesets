rule TTP_XOR_QUAD_CurrentVersionRun_927f {
  strings:
    $key_927f = { c1 10 [2] e5 1e [2] ce 32 [2] e0 10 [2] f4 0b [2] fb 11 [2] e5 0c [2] e7 0d [2] fc 0b [2] e0 0c [2] fc 23 }

  condition:
    any of them
}