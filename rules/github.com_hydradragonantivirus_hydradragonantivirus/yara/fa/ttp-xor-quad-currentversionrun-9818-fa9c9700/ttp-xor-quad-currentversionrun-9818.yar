rule TTP_XOR_QUAD_CurrentVersionRun_9818 {
  strings:
    $key_9818 = { cb 77 [2] ef 79 [2] c4 55 [2] ea 77 [2] fe 6c [2] f1 76 [2] ef 6b [2] ed 6a [2] f6 6c [2] ea 6b [2] f6 44 }

  condition:
    any of them
}