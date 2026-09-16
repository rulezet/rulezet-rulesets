rule TTP_XOR_QUAD_CurrentVersionRun_9841 {
  strings:
    $key_9841 = { cb 2e [2] ef 20 [2] c4 0c [2] ea 2e [2] fe 35 [2] f1 2f [2] ef 32 [2] ed 33 [2] f6 35 [2] ea 32 [2] f6 1d }

  condition:
    any of them
}