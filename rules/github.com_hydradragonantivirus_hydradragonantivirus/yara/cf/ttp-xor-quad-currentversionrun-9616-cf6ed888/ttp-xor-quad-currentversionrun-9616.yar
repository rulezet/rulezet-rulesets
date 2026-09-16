rule TTP_XOR_QUAD_CurrentVersionRun_9616 {
  strings:
    $key_9616 = { c5 79 [2] e1 77 [2] ca 5b [2] e4 79 [2] f0 62 [2] ff 78 [2] e1 65 [2] e3 64 [2] f8 62 [2] e4 65 [2] f8 4a }

  condition:
    any of them
}