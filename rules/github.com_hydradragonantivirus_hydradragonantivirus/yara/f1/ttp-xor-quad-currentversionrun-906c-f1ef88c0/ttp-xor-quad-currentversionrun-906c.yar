rule TTP_XOR_QUAD_CurrentVersionRun_906c {
  strings:
    $key_906c = { c3 03 [2] e7 0d [2] cc 21 [2] e2 03 [2] f6 18 [2] f9 02 [2] e7 1f [2] e5 1e [2] fe 18 [2] e2 1f [2] fe 30 }

  condition:
    any of them
}