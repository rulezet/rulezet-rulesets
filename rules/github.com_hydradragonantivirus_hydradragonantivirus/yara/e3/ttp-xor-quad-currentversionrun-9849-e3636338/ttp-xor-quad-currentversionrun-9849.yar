rule TTP_XOR_QUAD_CurrentVersionRun_9849 {
  strings:
    $key_9849 = { cb 26 [2] ef 28 [2] c4 04 [2] ea 26 [2] fe 3d [2] f1 27 [2] ef 3a [2] ed 3b [2] f6 3d [2] ea 3a [2] f6 15 }

  condition:
    any of them
}