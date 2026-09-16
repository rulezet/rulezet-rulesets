rule TTP_XOR_QUAD_CurrentVersionRun_88d7 {
  strings:
    $key_88d7 = { db b8 [2] ff b6 [2] d4 9a [2] fa b8 [2] ee a3 [2] e1 b9 [2] ff a4 [2] fd a5 [2] e6 a3 [2] fa a4 [2] e6 8b }

  condition:
    any of them
}