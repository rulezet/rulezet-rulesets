rule TTP_XOR_QUAD_CurrentVersionRun_985f {
  strings:
    $key_985f = { cb 30 [2] ef 3e [2] c4 12 [2] ea 30 [2] fe 2b [2] f1 31 [2] ef 2c [2] ed 2d [2] f6 2b [2] ea 2c [2] f6 03 }

  condition:
    any of them
}