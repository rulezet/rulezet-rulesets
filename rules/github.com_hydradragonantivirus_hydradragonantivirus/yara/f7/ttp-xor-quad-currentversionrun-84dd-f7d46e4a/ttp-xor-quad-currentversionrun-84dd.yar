rule TTP_XOR_QUAD_CurrentVersionRun_84dd {
  strings:
    $key_84dd = { d7 b2 [2] f3 bc [2] d8 90 [2] f6 b2 [2] e2 a9 [2] ed b3 [2] f3 ae [2] f1 af [2] ea a9 [2] f6 ae [2] ea 81 }

  condition:
    any of them
}