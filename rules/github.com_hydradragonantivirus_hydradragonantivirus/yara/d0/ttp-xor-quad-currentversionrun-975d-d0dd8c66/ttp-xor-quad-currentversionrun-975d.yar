rule TTP_XOR_QUAD_CurrentVersionRun_975d {
  strings:
    $key_975d = { c4 32 [2] e0 3c [2] cb 10 [2] e5 32 [2] f1 29 [2] fe 33 [2] e0 2e [2] e2 2f [2] f9 29 [2] e5 2e [2] f9 01 }

  condition:
    any of them
}