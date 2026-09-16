rule TTP_XOR_QUAD_CurrentVersionRun_16ad {
  strings:
    $key_16ad = { 45 c2 [2] 61 cc [2] 4a e0 [2] 64 c2 [2] 70 d9 [2] 7f c3 [2] 61 de [2] 63 df [2] 78 d9 [2] 64 de [2] 78 f1 }

  condition:
    any of them
}