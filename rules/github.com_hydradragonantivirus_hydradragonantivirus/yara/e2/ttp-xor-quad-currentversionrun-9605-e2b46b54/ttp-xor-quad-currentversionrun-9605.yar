rule TTP_XOR_QUAD_CurrentVersionRun_9605 {
  strings:
    $key_9605 = { c5 6a [2] e1 64 [2] ca 48 [2] e4 6a [2] f0 71 [2] ff 6b [2] e1 76 [2] e3 77 [2] f8 71 [2] e4 76 [2] f8 59 }

  condition:
    any of them
}