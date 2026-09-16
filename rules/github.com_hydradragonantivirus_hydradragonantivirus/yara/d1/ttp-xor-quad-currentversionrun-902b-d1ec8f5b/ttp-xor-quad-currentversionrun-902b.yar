rule TTP_XOR_QUAD_CurrentVersionRun_902b {
  strings:
    $key_902b = { c3 44 [2] e7 4a [2] cc 66 [2] e2 44 [2] f6 5f [2] f9 45 [2] e7 58 [2] e5 59 [2] fe 5f [2] e2 58 [2] fe 77 }

  condition:
    any of them
}