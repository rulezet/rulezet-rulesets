rule TTP_XOR_QUAD_CurrentVersionRun_902e {
  strings:
    $key_902e = { c3 41 [2] e7 4f [2] cc 63 [2] e2 41 [2] f6 5a [2] f9 40 [2] e7 5d [2] e5 5c [2] fe 5a [2] e2 5d [2] fe 72 }

  condition:
    any of them
}