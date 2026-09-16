rule TTP_XOR_QUAD_CurrentVersionRun_9614 {
  strings:
    $key_9614 = { c5 7b [2] e1 75 [2] ca 59 [2] e4 7b [2] f0 60 [2] ff 7a [2] e1 67 [2] e3 66 [2] f8 60 [2] e4 67 [2] f8 48 }

  condition:
    any of them
}