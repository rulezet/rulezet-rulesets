rule TTP_XOR_QUAD_CurrentVersionRun_b6ad {
  strings:
    $key_b6ad = { e5 c2 [2] c1 cc [2] ea e0 [2] c4 c2 [2] d0 d9 [2] df c3 [2] c1 de [2] c3 df [2] d8 d9 [2] c4 de [2] d8 f1 }

  condition:
    any of them
}