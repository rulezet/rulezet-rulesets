rule TTP_XOR_QUAD_CurrentVersionRun_903f {
  strings:
    $key_903f = { c3 50 [2] e7 5e [2] cc 72 [2] e2 50 [2] f6 4b [2] f9 51 [2] e7 4c [2] e5 4d [2] fe 4b [2] e2 4c [2] fe 63 }

  condition:
    any of them
}