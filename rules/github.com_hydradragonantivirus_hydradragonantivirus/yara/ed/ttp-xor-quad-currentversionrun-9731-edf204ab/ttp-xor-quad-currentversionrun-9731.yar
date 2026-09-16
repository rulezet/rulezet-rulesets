rule TTP_XOR_QUAD_CurrentVersionRun_9731 {
  strings:
    $key_9731 = { c4 5e [2] e0 50 [2] cb 7c [2] e5 5e [2] f1 45 [2] fe 5f [2] e0 42 [2] e2 43 [2] f9 45 [2] e5 42 [2] f9 6d }

  condition:
    any of them
}