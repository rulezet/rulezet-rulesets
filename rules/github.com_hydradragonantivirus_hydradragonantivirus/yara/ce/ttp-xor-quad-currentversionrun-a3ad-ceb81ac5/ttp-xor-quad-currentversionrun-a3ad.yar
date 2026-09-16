rule TTP_XOR_QUAD_CurrentVersionRun_a3ad {
  strings:
    $key_a3ad = { f0 c2 [2] d4 cc [2] ff e0 [2] d1 c2 [2] c5 d9 [2] ca c3 [2] d4 de [2] d6 df [2] cd d9 [2] d1 de [2] cd f1 }

  condition:
    any of them
}