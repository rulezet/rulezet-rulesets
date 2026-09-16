rule TTP_XOR_QUAD_CurrentVersionRun_bdb7 {
  strings:
    $key_bdb7 = { ee d8 [2] ca d6 [2] e1 fa [2] cf d8 [2] db c3 [2] d4 d9 [2] ca c4 [2] c8 c5 [2] d3 c3 [2] cf c4 [2] d3 eb }

  condition:
    any of them
}