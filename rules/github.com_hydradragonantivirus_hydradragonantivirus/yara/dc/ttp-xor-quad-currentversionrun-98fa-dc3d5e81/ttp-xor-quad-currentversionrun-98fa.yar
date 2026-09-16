rule TTP_XOR_QUAD_CurrentVersionRun_98fa {
  strings:
    $key_98fa = { cb 95 [2] ef 9b [2] c4 b7 [2] ea 95 [2] fe 8e [2] f1 94 [2] ef 89 [2] ed 88 [2] f6 8e [2] ea 89 [2] f6 a6 }

  condition:
    any of them
}