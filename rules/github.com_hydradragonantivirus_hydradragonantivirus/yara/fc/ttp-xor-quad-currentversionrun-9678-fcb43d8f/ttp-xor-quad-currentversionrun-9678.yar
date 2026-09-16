rule TTP_XOR_QUAD_CurrentVersionRun_9678 {
  strings:
    $key_9678 = { c5 17 [2] e1 19 [2] ca 35 [2] e4 17 [2] f0 0c [2] ff 16 [2] e1 0b [2] e3 0a [2] f8 0c [2] e4 0b [2] f8 24 }

  condition:
    any of them
}