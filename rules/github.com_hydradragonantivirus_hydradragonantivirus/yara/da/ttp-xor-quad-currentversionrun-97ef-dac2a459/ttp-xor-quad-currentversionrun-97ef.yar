rule TTP_XOR_QUAD_CurrentVersionRun_97ef {
  strings:
    $key_97ef = { c4 80 [2] e0 8e [2] cb a2 [2] e5 80 [2] f1 9b [2] fe 81 [2] e0 9c [2] e2 9d [2] f9 9b [2] e5 9c [2] f9 b3 }

  condition:
    any of them
}