rule TTP_XOR_QUAD_CurrentVersionRun_9636 {
  strings:
    $key_9636 = { c5 59 [2] e1 57 [2] ca 7b [2] e4 59 [2] f0 42 [2] ff 58 [2] e1 45 [2] e3 44 [2] f8 42 [2] e4 45 [2] f8 6a }

  condition:
    any of them
}