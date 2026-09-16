rule TTP_XOR_QUAD_CurrentVersionRun_977a {
  strings:
    $key_977a = { c4 15 [2] e0 1b [2] cb 37 [2] e5 15 [2] f1 0e [2] fe 14 [2] e0 09 [2] e2 08 [2] f9 0e [2] e5 09 [2] f9 26 }

  condition:
    any of them
}