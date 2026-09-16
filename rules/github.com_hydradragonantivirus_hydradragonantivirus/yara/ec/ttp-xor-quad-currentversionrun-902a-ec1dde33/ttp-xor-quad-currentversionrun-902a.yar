rule TTP_XOR_QUAD_CurrentVersionRun_902a {
  strings:
    $key_902a = { c3 45 [2] e7 4b [2] cc 67 [2] e2 45 [2] f6 5e [2] f9 44 [2] e7 59 [2] e5 58 [2] fe 5e [2] e2 59 [2] fe 76 }

  condition:
    any of them
}