rule TTP_XOR_QUAD_CurrentVersionRun_901d {
  strings:
    $key_901d = { c3 72 [2] e7 7c [2] cc 50 [2] e2 72 [2] f6 69 [2] f9 73 [2] e7 6e [2] e5 6f [2] fe 69 [2] e2 6e [2] fe 41 }

  condition:
    any of them
}