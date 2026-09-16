rule TTP_XOR_QUAD_CurrentVersionRun_9873 {
  strings:
    $key_9873 = { cb 1c [2] ef 12 [2] c4 3e [2] ea 1c [2] fe 07 [2] f1 1d [2] ef 00 [2] ed 01 [2] f6 07 [2] ea 00 [2] f6 2f }

  condition:
    any of them
}