rule TTP_XOR_QUAD_CurrentVersionRun_a9c8 {
  strings:
    $key_a9c8 = { fa a7 [2] de a9 [2] f5 85 [2] db a7 [2] cf bc [2] c0 a6 [2] de bb [2] dc ba [2] c7 bc [2] db bb [2] c7 94 }

  condition:
    any of them
}