rule TTP_XOR_QUAD_CurrentVersionRun_b2ad {
  strings:
    $key_b2ad = { e1 c2 [2] c5 cc [2] ee e0 [2] c0 c2 [2] d4 d9 [2] db c3 [2] c5 de [2] c7 df [2] dc d9 [2] c0 de [2] dc f1 }

  condition:
    any of them
}