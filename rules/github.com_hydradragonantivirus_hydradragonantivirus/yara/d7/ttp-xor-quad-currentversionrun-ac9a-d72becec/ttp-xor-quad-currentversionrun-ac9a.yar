rule TTP_XOR_QUAD_CurrentVersionRun_ac9a {
  strings:
    $key_ac9a = { ff f5 [2] db fb [2] f0 d7 [2] de f5 [2] ca ee [2] c5 f4 [2] db e9 [2] d9 e8 [2] c2 ee [2] de e9 [2] c2 c6 }

  condition:
    any of them
}