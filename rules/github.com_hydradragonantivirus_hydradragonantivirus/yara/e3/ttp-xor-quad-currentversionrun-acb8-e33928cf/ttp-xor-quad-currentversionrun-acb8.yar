rule TTP_XOR_QUAD_CurrentVersionRun_acb8 {
  strings:
    $key_acb8 = { ff d7 [2] db d9 [2] f0 f5 [2] de d7 [2] ca cc [2] c5 d6 [2] db cb [2] d9 ca [2] c2 cc [2] de cb [2] c2 e4 }

  condition:
    any of them
}