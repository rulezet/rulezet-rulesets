rule TTP_XOR_QUAD_CurrentVersionRun_88d5 {
  strings:
    $key_88d5 = { db ba [2] ff b4 [2] d4 98 [2] fa ba [2] ee a1 [2] e1 bb [2] ff a6 [2] fd a7 [2] e6 a1 [2] fa a6 [2] e6 89 }

  condition:
    any of them
}