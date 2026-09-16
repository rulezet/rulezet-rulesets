rule TTP_XOR_QUAD_CurrentVersionRun_9a43 {
  strings:
    $key_9a43 = { c9 2c [2] ed 22 [2] c6 0e [2] e8 2c [2] fc 37 [2] f3 2d [2] ed 30 [2] ef 31 [2] f4 37 [2] e8 30 [2] f4 1f }

  condition:
    any of them
}