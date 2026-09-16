rule TTP_XOR_QUAD_CurrentVersionRun_adad {
  strings:
    $key_adad = { fe c2 [2] da cc [2] f1 e0 [2] df c2 [2] cb d9 [2] c4 c3 [2] da de [2] d8 df [2] c3 d9 [2] df de [2] c3 f1 }

  condition:
    any of them
}