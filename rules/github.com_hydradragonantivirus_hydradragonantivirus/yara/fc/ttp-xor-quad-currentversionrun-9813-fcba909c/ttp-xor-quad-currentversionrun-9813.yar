rule TTP_XOR_QUAD_CurrentVersionRun_9813 {
  strings:
    $key_9813 = { cb 7c [2] ef 72 [2] c4 5e [2] ea 7c [2] fe 67 [2] f1 7d [2] ef 60 [2] ed 61 [2] f6 67 [2] ea 60 [2] f6 4f }

  condition:
    any of them
}