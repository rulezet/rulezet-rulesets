rule TTP_XOR_QUAD_CurrentVersionRun_aad3 {
  strings:
    $key_aad3 = { f9 bc [2] dd b2 [2] f6 9e [2] d8 bc [2] cc a7 [2] c3 bd [2] dd a0 [2] df a1 [2] c4 a7 [2] d8 a0 [2] c4 8f }

  condition:
    any of them
}