rule TTP_XOR_QUAD_CurrentVersionRun_973a {
  strings:
    $key_973a = { c4 55 [2] e0 5b [2] cb 77 [2] e5 55 [2] f1 4e [2] fe 54 [2] e0 49 [2] e2 48 [2] f9 4e [2] e5 49 [2] f9 66 }

  condition:
    any of them
}