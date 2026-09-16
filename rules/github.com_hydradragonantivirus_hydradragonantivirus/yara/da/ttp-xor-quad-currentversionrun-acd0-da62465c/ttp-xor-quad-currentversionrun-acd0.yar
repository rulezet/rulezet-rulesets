rule TTP_XOR_QUAD_CurrentVersionRun_acd0 {
  strings:
    $key_acd0 = { ff bf [2] db b1 [2] f0 9d [2] de bf [2] ca a4 [2] c5 be [2] db a3 [2] d9 a2 [2] c2 a4 [2] de a3 [2] c2 8c }

  condition:
    any of them
}