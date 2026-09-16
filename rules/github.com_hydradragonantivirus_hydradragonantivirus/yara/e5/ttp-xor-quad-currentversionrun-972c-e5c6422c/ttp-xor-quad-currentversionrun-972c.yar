rule TTP_XOR_QUAD_CurrentVersionRun_972c {
  strings:
    $key_972c = { c4 43 [2] e0 4d [2] cb 61 [2] e5 43 [2] f1 58 [2] fe 42 [2] e0 5f [2] e2 5e [2] f9 58 [2] e5 5f [2] f9 70 }

  condition:
    any of them
}