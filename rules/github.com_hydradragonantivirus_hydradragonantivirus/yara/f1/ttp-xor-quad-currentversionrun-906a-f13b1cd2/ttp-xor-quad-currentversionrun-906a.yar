rule TTP_XOR_QUAD_CurrentVersionRun_906a {
  strings:
    $key_906a = { c3 05 [2] e7 0b [2] cc 27 [2] e2 05 [2] f6 1e [2] f9 04 [2] e7 19 [2] e5 18 [2] fe 1e [2] e2 19 [2] fe 36 }

  condition:
    any of them
}