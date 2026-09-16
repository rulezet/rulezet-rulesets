rule TTP_XOR_QUAD_CurrentVersionRun_aad6 {
  strings:
    $key_aad6 = { f9 b9 [2] dd b7 [2] f6 9b [2] d8 b9 [2] cc a2 [2] c3 b8 [2] dd a5 [2] df a4 [2] c4 a2 [2] d8 a5 [2] c4 8a }

  condition:
    any of them
}