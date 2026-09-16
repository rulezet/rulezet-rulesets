rule TTP_XOR_QUAD_CurrentVersionRun_9658 {
  strings:
    $key_9658 = { c5 37 [2] e1 39 [2] ca 15 [2] e4 37 [2] f0 2c [2] ff 36 [2] e1 2b [2] e3 2a [2] f8 2c [2] e4 2b [2] f8 04 }

  condition:
    any of them
}