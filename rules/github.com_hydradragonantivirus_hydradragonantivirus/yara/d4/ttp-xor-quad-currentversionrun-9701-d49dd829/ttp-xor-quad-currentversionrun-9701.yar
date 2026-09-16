rule TTP_XOR_QUAD_CurrentVersionRun_9701 {
  strings:
    $key_9701 = { c4 6e [2] e0 60 [2] cb 4c [2] e5 6e [2] f1 75 [2] fe 6f [2] e0 72 [2] e2 73 [2] f9 75 [2] e5 72 [2] f9 5d }

  condition:
    any of them
}