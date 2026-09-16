rule TTP_XOR_QUAD_CurrentVersionRun_987c {
  strings:
    $key_987c = { cb 13 [2] ef 1d [2] c4 31 [2] ea 13 [2] fe 08 [2] f1 12 [2] ef 0f [2] ed 0e [2] f6 08 [2] ea 0f [2] f6 20 }

  condition:
    any of them
}