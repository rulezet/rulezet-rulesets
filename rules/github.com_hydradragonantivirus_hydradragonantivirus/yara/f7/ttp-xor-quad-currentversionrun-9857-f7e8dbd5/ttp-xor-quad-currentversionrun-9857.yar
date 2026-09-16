rule TTP_XOR_QUAD_CurrentVersionRun_9857 {
  strings:
    $key_9857 = { cb 38 [2] ef 36 [2] c4 1a [2] ea 38 [2] fe 23 [2] f1 39 [2] ef 24 [2] ed 25 [2] f6 23 [2] ea 24 [2] f6 0b }

  condition:
    any of them
}