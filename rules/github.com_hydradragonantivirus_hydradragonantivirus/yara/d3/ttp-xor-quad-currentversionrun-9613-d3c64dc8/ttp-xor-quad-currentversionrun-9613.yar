rule TTP_XOR_QUAD_CurrentVersionRun_9613 {
  strings:
    $key_9613 = { c5 7c [2] e1 72 [2] ca 5e [2] e4 7c [2] f0 67 [2] ff 7d [2] e1 60 [2] e3 61 [2] f8 67 [2] e4 60 [2] f8 4f }

  condition:
    any of them
}