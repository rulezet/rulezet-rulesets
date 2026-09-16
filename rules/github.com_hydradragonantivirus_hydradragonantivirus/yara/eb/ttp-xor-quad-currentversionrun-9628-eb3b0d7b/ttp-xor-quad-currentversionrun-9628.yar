rule TTP_XOR_QUAD_CurrentVersionRun_9628 {
  strings:
    $key_9628 = { c5 47 [2] e1 49 [2] ca 65 [2] e4 47 [2] f0 5c [2] ff 46 [2] e1 5b [2] e3 5a [2] f8 5c [2] e4 5b [2] f8 74 }

  condition:
    any of them
}