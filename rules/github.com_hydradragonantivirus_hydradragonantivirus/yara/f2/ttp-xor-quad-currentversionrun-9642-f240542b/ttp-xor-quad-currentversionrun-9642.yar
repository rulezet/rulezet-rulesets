rule TTP_XOR_QUAD_CurrentVersionRun_9642 {
  strings:
    $key_9642 = { c5 2d [2] e1 23 [2] ca 0f [2] e4 2d [2] f0 36 [2] ff 2c [2] e1 31 [2] e3 30 [2] f8 36 [2] e4 31 [2] f8 1e }

  condition:
    any of them
}