rule TTP_XOR_QUAD_CurrentVersionRun_9615 {
  strings:
    $key_9615 = { c5 7a [2] e1 74 [2] ca 58 [2] e4 7a [2] f0 61 [2] ff 7b [2] e1 66 [2] e3 67 [2] f8 61 [2] e4 66 [2] f8 49 }

  condition:
    any of them
}