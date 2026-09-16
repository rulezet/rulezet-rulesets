rule TTP_XOR_QUAD_CurrentVersionRun_927e {
  strings:
    $key_927e = { c1 11 [2] e5 1f [2] ce 33 [2] e0 11 [2] f4 0a [2] fb 10 [2] e5 0d [2] e7 0c [2] fc 0a [2] e0 0d [2] fc 22 }

  condition:
    any of them
}