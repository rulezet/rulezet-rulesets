rule TTP_XOR_QUAD_CurrentVersionRun_afc6 {
  strings:
    $key_afc6 = { fc a9 [2] d8 a7 [2] f3 8b [2] dd a9 [2] c9 b2 [2] c6 a8 [2] d8 b5 [2] da b4 [2] c1 b2 [2] dd b5 [2] c1 9a }

  condition:
    any of them
}