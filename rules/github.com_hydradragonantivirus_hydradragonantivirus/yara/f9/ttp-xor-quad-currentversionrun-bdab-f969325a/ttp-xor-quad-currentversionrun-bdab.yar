rule TTP_XOR_QUAD_CurrentVersionRun_bdab {
  strings:
    $key_bdab = { ee c4 [2] ca ca [2] e1 e6 [2] cf c4 [2] db df [2] d4 c5 [2] ca d8 [2] c8 d9 [2] d3 df [2] cf d8 [2] d3 f7 }

  condition:
    any of them
}