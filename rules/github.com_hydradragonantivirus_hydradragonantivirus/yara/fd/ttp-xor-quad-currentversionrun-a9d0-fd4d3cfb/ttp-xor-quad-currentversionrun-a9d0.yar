rule TTP_XOR_QUAD_CurrentVersionRun_a9d0 {
  strings:
    $key_a9d0 = { fa bf [2] de b1 [2] f5 9d [2] db bf [2] cf a4 [2] c0 be [2] de a3 [2] dc a2 [2] c7 a4 [2] db a3 [2] c7 8c }

  condition:
    any of them
}