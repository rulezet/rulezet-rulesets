rule TTP_XOR_QUAD_CurrentVersionRun_903a {
  strings:
    $key_903a = { c3 55 [2] e7 5b [2] cc 77 [2] e2 55 [2] f6 4e [2] f9 54 [2] e7 49 [2] e5 48 [2] fe 4e [2] e2 49 [2] fe 66 }

  condition:
    any of them
}