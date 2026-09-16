rule TTP_XOR_QUAD_CurrentVersionRun_9710 {
  strings:
    $key_9710 = { c4 7f [2] e0 71 [2] cb 5d [2] e5 7f [2] f1 64 [2] fe 7e [2] e0 63 [2] e2 62 [2] f9 64 [2] e5 63 [2] f9 4c }

  condition:
    any of them
}