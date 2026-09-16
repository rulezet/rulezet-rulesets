rule TTP_XOR_QUAD_CurrentVersionRun_9625 {
  strings:
    $key_9625 = { c5 4a [2] e1 44 [2] ca 68 [2] e4 4a [2] f0 51 [2] ff 4b [2] e1 56 [2] e3 57 [2] f8 51 [2] e4 56 [2] f8 79 }

  condition:
    any of them
}