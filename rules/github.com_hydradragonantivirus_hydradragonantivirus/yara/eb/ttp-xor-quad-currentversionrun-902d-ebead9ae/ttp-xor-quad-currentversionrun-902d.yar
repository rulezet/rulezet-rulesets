rule TTP_XOR_QUAD_CurrentVersionRun_902d {
  strings:
    $key_902d = { c3 42 [2] e7 4c [2] cc 60 [2] e2 42 [2] f6 59 [2] f9 43 [2] e7 5e [2] e5 5f [2] fe 59 [2] e2 5e [2] fe 71 }

  condition:
    any of them
}