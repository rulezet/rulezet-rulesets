rule TTP_XOR_QUAD_CurrentVersionRun_9733 {
  strings:
    $key_9733 = { c4 5c [2] e0 52 [2] cb 7e [2] e5 5c [2] f1 47 [2] fe 5d [2] e0 40 [2] e2 41 [2] f9 47 [2] e5 40 [2] f9 6f }

  condition:
    any of them
}