rule TTP_XOR_QUAD_CurrentVersionRun_9859 {
  strings:
    $key_9859 = { cb 36 [2] ef 38 [2] c4 14 [2] ea 36 [2] fe 2d [2] f1 37 [2] ef 2a [2] ed 2b [2] f6 2d [2] ea 2a [2] f6 05 }

  condition:
    any of them
}