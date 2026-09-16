rule TTP_XOR_QUAD_CurrentVersionRun_9674 {
  strings:
    $key_9674 = { c5 1b [2] e1 15 [2] ca 39 [2] e4 1b [2] f0 00 [2] ff 1a [2] e1 07 [2] e3 06 [2] f8 00 [2] e4 07 [2] f8 28 }

  condition:
    any of them
}