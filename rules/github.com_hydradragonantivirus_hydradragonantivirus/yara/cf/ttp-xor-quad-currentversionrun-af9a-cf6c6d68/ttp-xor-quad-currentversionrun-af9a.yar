rule TTP_XOR_QUAD_CurrentVersionRun_af9a {
  strings:
    $key_af9a = { fc f5 [2] d8 fb [2] f3 d7 [2] dd f5 [2] c9 ee [2] c6 f4 [2] d8 e9 [2] da e8 [2] c1 ee [2] dd e9 [2] c1 c6 }

  condition:
    any of them
}