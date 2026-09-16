rule TTP_XOR_QUAD_CurrentVersionRun_9868 {
  strings:
    $key_9868 = { cb 07 [2] ef 09 [2] c4 25 [2] ea 07 [2] fe 1c [2] f1 06 [2] ef 1b [2] ed 1a [2] f6 1c [2] ea 1b [2] f6 34 }

  condition:
    any of them
}