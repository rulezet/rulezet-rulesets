rule TTP_XOR_QUAD_CurrentVersionRun_9848 {
  strings:
    $key_9848 = { cb 27 [2] ef 29 [2] c4 05 [2] ea 27 [2] fe 3c [2] f1 26 [2] ef 3b [2] ed 3a [2] f6 3c [2] ea 3b [2] f6 14 }

  condition:
    any of them
}