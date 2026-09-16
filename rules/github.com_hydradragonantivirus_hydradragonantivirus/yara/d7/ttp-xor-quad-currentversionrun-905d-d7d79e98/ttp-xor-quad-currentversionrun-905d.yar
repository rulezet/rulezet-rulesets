rule TTP_XOR_QUAD_CurrentVersionRun_905d {
  strings:
    $key_905d = { c3 32 [2] e7 3c [2] cc 10 [2] e2 32 [2] f6 29 [2] f9 33 [2] e7 2e [2] e5 2f [2] fe 29 [2] e2 2e [2] fe 01 }

  condition:
    any of them
}