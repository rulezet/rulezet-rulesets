rule TTP_XOR_QUAD_CurrentVersionRun_9829 {
  strings:
    $key_9829 = { cb 46 [2] ef 48 [2] c4 64 [2] ea 46 [2] fe 5d [2] f1 47 [2] ef 5a [2] ed 5b [2] f6 5d [2] ea 5a [2] f6 75 }

  condition:
    any of them
}