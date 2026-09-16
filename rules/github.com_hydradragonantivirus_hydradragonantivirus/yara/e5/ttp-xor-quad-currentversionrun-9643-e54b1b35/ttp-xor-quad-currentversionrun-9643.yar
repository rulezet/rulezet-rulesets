rule TTP_XOR_QUAD_CurrentVersionRun_9643 {
  strings:
    $key_9643 = { c5 2c [2] e1 22 [2] ca 0e [2] e4 2c [2] f0 37 [2] ff 2d [2] e1 30 [2] e3 31 [2] f8 37 [2] e4 30 [2] f8 1f }

  condition:
    any of them
}