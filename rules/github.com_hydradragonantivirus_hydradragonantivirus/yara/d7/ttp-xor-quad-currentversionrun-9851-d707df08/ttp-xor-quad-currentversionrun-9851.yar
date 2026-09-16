rule TTP_XOR_QUAD_CurrentVersionRun_9851 {
  strings:
    $key_9851 = { cb 3e [2] ef 30 [2] c4 1c [2] ea 3e [2] fe 25 [2] f1 3f [2] ef 22 [2] ed 23 [2] f6 25 [2] ea 22 [2] f6 0d }

  condition:
    any of them
}