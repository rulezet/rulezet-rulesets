rule TTP_XOR_QUAD_CurrentVersionRun_bd99 {
  strings:
    $key_bd99 = { ee f6 [2] ca f8 [2] e1 d4 [2] cf f6 [2] db ed [2] d4 f7 [2] ca ea [2] c8 eb [2] d3 ed [2] cf ea [2] d3 c5 }

  condition:
    any of them
}