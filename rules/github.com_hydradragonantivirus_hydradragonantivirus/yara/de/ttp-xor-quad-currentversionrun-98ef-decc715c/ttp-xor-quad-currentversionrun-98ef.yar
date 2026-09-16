rule TTP_XOR_QUAD_CurrentVersionRun_98ef {
  strings:
    $key_98ef = { cb 80 [2] ef 8e [2] c4 a2 [2] ea 80 [2] fe 9b [2] f1 81 [2] ef 9c [2] ed 9d [2] f6 9b [2] ea 9c [2] f6 b3 }

  condition:
    any of them
}