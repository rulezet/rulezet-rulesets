rule TTP_XOR_QUAD_CurrentVersionRun_9742 {
  strings:
    $key_9742 = { c4 2d [2] e0 23 [2] cb 0f [2] e5 2d [2] f1 36 [2] fe 2c [2] e0 31 [2] e2 30 [2] f9 36 [2] e5 31 [2] f9 1e }

  condition:
    any of them
}