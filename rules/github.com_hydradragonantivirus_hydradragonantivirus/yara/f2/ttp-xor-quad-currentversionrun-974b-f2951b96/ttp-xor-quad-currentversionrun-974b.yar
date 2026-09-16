rule TTP_XOR_QUAD_CurrentVersionRun_974b {
  strings:
    $key_974b = { c4 24 [2] e0 2a [2] cb 06 [2] e5 24 [2] f1 3f [2] fe 25 [2] e0 38 [2] e2 39 [2] f9 3f [2] e5 38 [2] f9 17 }

  condition:
    any of them
}