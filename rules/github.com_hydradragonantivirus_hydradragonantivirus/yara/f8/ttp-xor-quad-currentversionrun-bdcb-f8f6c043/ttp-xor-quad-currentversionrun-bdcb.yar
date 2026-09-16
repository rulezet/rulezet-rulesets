rule TTP_XOR_QUAD_CurrentVersionRun_bdcb {
  strings:
    $key_bdcb = { ee a4 [2] ca aa [2] e1 86 [2] cf a4 [2] db bf [2] d4 a5 [2] ca b8 [2] c8 b9 [2] d3 bf [2] cf b8 [2] d3 97 }

  condition:
    any of them
}