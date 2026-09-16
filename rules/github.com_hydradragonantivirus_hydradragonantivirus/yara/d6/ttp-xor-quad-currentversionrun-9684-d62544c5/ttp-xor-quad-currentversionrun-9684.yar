rule TTP_XOR_QUAD_CurrentVersionRun_9684 {
  strings:
    $key_9684 = { c5 eb [2] e1 e5 [2] ca c9 [2] e4 eb [2] f0 f0 [2] ff ea [2] e1 f7 [2] e3 f6 [2] f8 f0 [2] e4 f7 [2] f8 d8 }

  condition:
    any of them
}