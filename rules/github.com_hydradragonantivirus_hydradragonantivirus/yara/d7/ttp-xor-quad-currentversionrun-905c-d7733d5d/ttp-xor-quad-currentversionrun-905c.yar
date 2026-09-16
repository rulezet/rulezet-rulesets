rule TTP_XOR_QUAD_CurrentVersionRun_905c {
  strings:
    $key_905c = { c3 33 [2] e7 3d [2] cc 11 [2] e2 33 [2] f6 28 [2] f9 32 [2] e7 2f [2] e5 2e [2] fe 28 [2] e2 2f [2] fe 00 }

  condition:
    any of them
}