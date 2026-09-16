rule TTP_XOR_QUAD_CurrentVersionRun_96dd {
  strings:
    $key_96dd = { c5 b2 [2] e1 bc [2] ca 90 [2] e4 b2 [2] f0 a9 [2] ff b3 [2] e1 ae [2] e3 af [2] f8 a9 [2] e4 ae [2] f8 81 }

  condition:
    any of them
}