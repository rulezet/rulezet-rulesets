rule TTP_XOR_QUAD_CurrentVersionRun_acd7 {
  strings:
    $key_acd7 = { ff b8 [2] db b6 [2] f0 9a [2] de b8 [2] ca a3 [2] c5 b9 [2] db a4 [2] d9 a5 [2] c2 a3 [2] de a4 [2] c2 8b }

  condition:
    any of them
}