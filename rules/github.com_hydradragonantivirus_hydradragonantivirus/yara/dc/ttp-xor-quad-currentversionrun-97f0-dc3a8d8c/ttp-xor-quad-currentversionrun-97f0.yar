rule TTP_XOR_QUAD_CurrentVersionRun_97f0 {
  strings:
    $key_97f0 = { c4 9f [2] e0 91 [2] cb bd [2] e5 9f [2] f1 84 [2] fe 9e [2] e0 83 [2] e2 82 [2] f9 84 [2] e5 83 [2] f9 ac }

  condition:
    any of them
}