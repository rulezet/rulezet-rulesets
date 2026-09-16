rule TTP_XOR_QUAD_CurrentVersionRun_af80 {
  strings:
    $key_af80 = { fc ef [2] d8 e1 [2] f3 cd [2] dd ef [2] c9 f4 [2] c6 ee [2] d8 f3 [2] da f2 [2] c1 f4 [2] dd f3 [2] c1 dc }

  condition:
    any of them
}