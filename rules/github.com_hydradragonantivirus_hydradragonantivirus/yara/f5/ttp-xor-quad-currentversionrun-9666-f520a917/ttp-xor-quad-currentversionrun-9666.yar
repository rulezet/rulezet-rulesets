rule TTP_XOR_QUAD_CurrentVersionRun_9666 {
  strings:
    $key_9666 = { c5 09 [2] e1 07 [2] ca 2b [2] e4 09 [2] f0 12 [2] ff 08 [2] e1 15 [2] e3 14 [2] f8 12 [2] e4 15 [2] f8 3a }

  condition:
    any of them
}