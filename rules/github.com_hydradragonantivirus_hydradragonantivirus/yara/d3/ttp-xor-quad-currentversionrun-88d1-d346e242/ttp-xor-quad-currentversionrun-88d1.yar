rule TTP_XOR_QUAD_CurrentVersionRun_88d1 {
  strings:
    $key_88d1 = { db be [2] ff b0 [2] d4 9c [2] fa be [2] ee a5 [2] e1 bf [2] ff a2 [2] fd a3 [2] e6 a5 [2] fa a2 [2] e6 8d }

  condition:
    any of them
}