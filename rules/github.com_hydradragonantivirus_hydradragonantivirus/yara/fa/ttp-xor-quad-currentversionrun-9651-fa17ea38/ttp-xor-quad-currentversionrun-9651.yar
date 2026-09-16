rule TTP_XOR_QUAD_CurrentVersionRun_9651 {
  strings:
    $key_9651 = { c5 3e [2] e1 30 [2] ca 1c [2] e4 3e [2] f0 25 [2] ff 3f [2] e1 22 [2] e3 23 [2] f8 25 [2] e4 22 [2] f8 0d }

  condition:
    any of them
}