rule TTP_XOR_QUAD_CurrentVersionRun_971b {
  strings:
    $key_971b = { c4 74 [2] e0 7a [2] cb 56 [2] e5 74 [2] f1 6f [2] fe 75 [2] e0 68 [2] e2 69 [2] f9 6f [2] e5 68 [2] f9 47 }

  condition:
    any of them
}