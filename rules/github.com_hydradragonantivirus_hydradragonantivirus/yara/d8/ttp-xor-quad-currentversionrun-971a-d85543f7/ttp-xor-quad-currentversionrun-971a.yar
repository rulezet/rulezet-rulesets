rule TTP_XOR_QUAD_CurrentVersionRun_971a {
  strings:
    $key_971a = { c4 75 [2] e0 7b [2] cb 57 [2] e5 75 [2] f1 6e [2] fe 74 [2] e0 69 [2] e2 68 [2] f9 6e [2] e5 69 [2] f9 46 }

  condition:
    any of them
}