rule TTP_XOR_QUAD_CurrentVersionRun_9782 {
  strings:
    $key_9782 = { c4 ed [2] e0 e3 [2] cb cf [2] e5 ed [2] f1 f6 [2] fe ec [2] e0 f1 [2] e2 f0 [2] f9 f6 [2] e5 f1 [2] f9 de }

  condition:
    any of them
}