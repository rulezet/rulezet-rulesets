rule TTP_XOR_QUAD_CurrentVersionRun_987f {
  strings:
    $key_987f = { cb 10 [2] ef 1e [2] c4 32 [2] ea 10 [2] fe 0b [2] f1 11 [2] ef 0c [2] ed 0d [2] f6 0b [2] ea 0c [2] f6 23 }

  condition:
    any of them
}