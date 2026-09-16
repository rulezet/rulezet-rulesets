rule TTP_XOR_QUAD_CurrentVersionRun_974d {
  strings:
    $key_974d = { c4 22 [2] e0 2c [2] cb 00 [2] e5 22 [2] f1 39 [2] fe 23 [2] e0 3e [2] e2 3f [2] f9 39 [2] e5 3e [2] f9 11 }

  condition:
    any of them
}