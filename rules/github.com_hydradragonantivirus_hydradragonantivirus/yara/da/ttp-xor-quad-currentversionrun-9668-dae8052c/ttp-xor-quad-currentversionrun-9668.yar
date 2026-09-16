rule TTP_XOR_QUAD_CurrentVersionRun_9668 {
  strings:
    $key_9668 = { c5 07 [2] e1 09 [2] ca 25 [2] e4 07 [2] f0 1c [2] ff 06 [2] e1 1b [2] e3 1a [2] f8 1c [2] e4 1b [2] f8 34 }

  condition:
    any of them
}