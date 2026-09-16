rule TTP_XOR_QUAD_CurrentVersionRun_afc7 {
  strings:
    $key_afc7 = { fc a8 [2] d8 a6 [2] f3 8a [2] dd a8 [2] c9 b3 [2] c6 a9 [2] d8 b4 [2] da b5 [2] c1 b3 [2] dd b4 [2] c1 9b }

  condition:
    any of them
}