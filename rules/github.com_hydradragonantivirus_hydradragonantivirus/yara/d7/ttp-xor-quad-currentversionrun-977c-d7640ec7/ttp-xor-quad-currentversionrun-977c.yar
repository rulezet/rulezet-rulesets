rule TTP_XOR_QUAD_CurrentVersionRun_977c {
  strings:
    $key_977c = { c4 13 [2] e0 1d [2] cb 31 [2] e5 13 [2] f1 08 [2] fe 12 [2] e0 0f [2] e2 0e [2] f9 08 [2] e5 0f [2] f9 20 }

  condition:
    any of them
}