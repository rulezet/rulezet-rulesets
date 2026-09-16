rule TTP_XOR_QUAD_CurrentVersionRun_922e {
  strings:
    $key_922e = { c1 41 [2] e5 4f [2] ce 63 [2] e0 41 [2] f4 5a [2] fb 40 [2] e5 5d [2] e7 5c [2] fc 5a [2] e0 5d [2] fc 72 }

  condition:
    any of them
}