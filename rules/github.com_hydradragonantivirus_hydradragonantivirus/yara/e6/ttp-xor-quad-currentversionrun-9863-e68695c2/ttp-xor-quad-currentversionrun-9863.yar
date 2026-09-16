rule TTP_XOR_QUAD_CurrentVersionRun_9863 {
  strings:
    $key_9863 = { cb 0c [2] ef 02 [2] c4 2e [2] ea 0c [2] fe 17 [2] f1 0d [2] ef 10 [2] ed 11 [2] f6 17 [2] ea 10 [2] f6 3f }

  condition:
    any of them
}