rule TTP_XOR_QUAD_CurrentVersionRun_9787 {
  strings:
    $key_9787 = { c4 e8 [2] e0 e6 [2] cb ca [2] e5 e8 [2] f1 f3 [2] fe e9 [2] e0 f4 [2] e2 f5 [2] f9 f3 [2] e5 f4 [2] f9 db }

  condition:
    any of them
}