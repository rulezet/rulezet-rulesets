rule TTP_XOR_QUAD_CurrentVersionRun_9650 {
  strings:
    $key_9650 = { c5 3f [2] e1 31 [2] ca 1d [2] e4 3f [2] f0 24 [2] ff 3e [2] e1 23 [2] e3 22 [2] f8 24 [2] e4 23 [2] f8 0c }

  condition:
    any of them
}