rule TTP_XOR_QUAD_CurrentVersionRun_88d6 {
  strings:
    $key_88d6 = { db b9 [2] ff b7 [2] d4 9b [2] fa b9 [2] ee a2 [2] e1 b8 [2] ff a5 [2] fd a4 [2] e6 a2 [2] fa a5 [2] e6 8a }

  condition:
    any of them
}