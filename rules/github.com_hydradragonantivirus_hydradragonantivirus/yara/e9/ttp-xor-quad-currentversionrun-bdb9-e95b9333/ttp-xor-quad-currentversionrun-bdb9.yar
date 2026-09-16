rule TTP_XOR_QUAD_CurrentVersionRun_bdb9 {
  strings:
    $key_bdb9 = { ee d6 [2] ca d8 [2] e1 f4 [2] cf d6 [2] db cd [2] d4 d7 [2] ca ca [2] c8 cb [2] d3 cd [2] cf ca [2] d3 e5 }

  condition:
    any of them
}