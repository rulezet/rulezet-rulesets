rule TTP_XOR_QUAD_CurrentVersionRun_b1dd {
  strings:
    $key_b1dd = { e2 b2 [2] c6 bc [2] ed 90 [2] c3 b2 [2] d7 a9 [2] d8 b3 [2] c6 ae [2] c4 af [2] df a9 [2] c3 ae [2] df 81 }

  condition:
    any of them
}