rule TTP_XOR_QUAD_CurrentVersionRun_9812 {
  strings:
    $key_9812 = { cb 7d [2] ef 73 [2] c4 5f [2] ea 7d [2] fe 66 [2] f1 7c [2] ef 61 [2] ed 60 [2] f6 66 [2] ea 61 [2] f6 4e }

  condition:
    any of them
}