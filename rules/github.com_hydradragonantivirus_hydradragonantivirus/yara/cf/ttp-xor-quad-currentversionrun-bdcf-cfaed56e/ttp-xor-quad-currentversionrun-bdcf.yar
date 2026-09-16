rule TTP_XOR_QUAD_CurrentVersionRun_bdcf {
  strings:
    $key_bdcf = { ee a0 [2] ca ae [2] e1 82 [2] cf a0 [2] db bb [2] d4 a1 [2] ca bc [2] c8 bd [2] d3 bb [2] cf bc [2] d3 93 }

  condition:
    any of them
}