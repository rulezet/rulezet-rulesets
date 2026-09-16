rule TTP_XOR_QUAD_CurrentVersionRun_9862 {
  strings:
    $key_9862 = { cb 0d [2] ef 03 [2] c4 2f [2] ea 0d [2] fe 16 [2] f1 0c [2] ef 11 [2] ed 10 [2] f6 16 [2] ea 11 [2] f6 3e }

  condition:
    any of them
}