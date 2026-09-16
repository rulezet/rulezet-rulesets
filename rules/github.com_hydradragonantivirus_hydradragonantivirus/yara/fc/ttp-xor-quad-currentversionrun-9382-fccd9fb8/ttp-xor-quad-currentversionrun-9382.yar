rule TTP_XOR_QUAD_CurrentVersionRun_9382 {
  strings:
    $key_9382 = { c0 ed [2] e4 e3 [2] cf cf [2] e1 ed [2] f5 f6 [2] fa ec [2] e4 f1 [2] e6 f0 [2] fd f6 [2] e1 f1 [2] fd de }

  condition:
    any of them
}