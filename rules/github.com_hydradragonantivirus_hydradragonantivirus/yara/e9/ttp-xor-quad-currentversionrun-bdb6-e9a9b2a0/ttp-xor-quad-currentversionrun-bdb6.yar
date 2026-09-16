rule TTP_XOR_QUAD_CurrentVersionRun_bdb6 {
  strings:
    $key_bdb6 = { ee d9 [2] ca d7 [2] e1 fb [2] cf d9 [2] db c2 [2] d4 d8 [2] ca c5 [2] c8 c4 [2] d3 c2 [2] cf c5 [2] d3 ea }

  condition:
    any of them
}