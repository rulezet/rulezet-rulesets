rule TTP_XOR_QUAD_CurrentVersionRun_acdb {
  strings:
    $key_acdb = { ff b4 [2] db ba [2] f0 96 [2] de b4 [2] ca af [2] c5 b5 [2] db a8 [2] d9 a9 [2] c2 af [2] de a8 [2] c2 87 }

  condition:
    any of them
}