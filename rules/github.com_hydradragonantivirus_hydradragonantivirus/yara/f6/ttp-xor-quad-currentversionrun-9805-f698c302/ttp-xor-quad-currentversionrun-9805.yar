rule TTP_XOR_QUAD_CurrentVersionRun_9805 {
  strings:
    $key_9805 = { cb 6a [2] ef 64 [2] c4 48 [2] ea 6a [2] fe 71 [2] f1 6b [2] ef 76 [2] ed 77 [2] f6 71 [2] ea 76 [2] f6 59 }

  condition:
    any of them
}