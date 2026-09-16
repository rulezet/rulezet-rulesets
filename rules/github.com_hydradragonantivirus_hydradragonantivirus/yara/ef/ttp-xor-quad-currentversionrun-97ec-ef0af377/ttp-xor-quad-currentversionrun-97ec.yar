rule TTP_XOR_QUAD_CurrentVersionRun_97ec {
  strings:
    $key_97ec = { c4 83 [2] e0 8d [2] cb a1 [2] e5 83 [2] f1 98 [2] fe 82 [2] e0 9f [2] e2 9e [2] f9 98 [2] e5 9f [2] f9 b0 }

  condition:
    any of them
}