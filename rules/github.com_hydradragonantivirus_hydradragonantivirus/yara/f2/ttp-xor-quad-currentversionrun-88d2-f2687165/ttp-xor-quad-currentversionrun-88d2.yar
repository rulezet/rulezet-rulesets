rule TTP_XOR_QUAD_CurrentVersionRun_88d2 {
  strings:
    $key_88d2 = { db bd [2] ff b3 [2] d4 9f [2] fa bd [2] ee a6 [2] e1 bc [2] ff a1 [2] fd a0 [2] e6 a6 [2] fa a1 [2] e6 8e }

  condition:
    any of them
}