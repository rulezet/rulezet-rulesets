rule TTP_XOR_QUAD_CurrentVersionRun_97ed {
  strings:
    $key_97ed = { c4 82 [2] e0 8c [2] cb a0 [2] e5 82 [2] f1 99 [2] fe 83 [2] e0 9e [2] e2 9f [2] f9 99 [2] e5 9e [2] f9 b1 }

  condition:
    any of them
}