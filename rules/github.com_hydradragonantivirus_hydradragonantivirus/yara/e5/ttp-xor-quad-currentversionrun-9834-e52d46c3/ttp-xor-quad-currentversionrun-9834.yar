rule TTP_XOR_QUAD_CurrentVersionRun_9834 {
  strings:
    $key_9834 = { cb 5b [2] ef 55 [2] c4 79 [2] ea 5b [2] fe 40 [2] f1 5a [2] ef 47 [2] ed 46 [2] f6 40 [2] ea 47 [2] f6 68 }

  condition:
    any of them
}