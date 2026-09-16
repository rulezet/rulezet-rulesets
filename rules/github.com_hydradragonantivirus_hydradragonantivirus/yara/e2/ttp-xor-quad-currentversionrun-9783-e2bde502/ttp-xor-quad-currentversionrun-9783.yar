rule TTP_XOR_QUAD_CurrentVersionRun_9783 {
  strings:
    $key_9783 = { c4 ec [2] e0 e2 [2] cb ce [2] e5 ec [2] f1 f7 [2] fe ed [2] e0 f0 [2] e2 f1 [2] f9 f7 [2] e5 f0 [2] f9 df }

  condition:
    any of them
}