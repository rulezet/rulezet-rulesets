rule TTP_XOR_QUAD_CurrentVersionRun_a9d7 {
  strings:
    $key_a9d7 = { fa b8 [2] de b6 [2] f5 9a [2] db b8 [2] cf a3 [2] c0 b9 [2] de a4 [2] dc a5 [2] c7 a3 [2] db a4 [2] c7 8b }

  condition:
    any of them
}