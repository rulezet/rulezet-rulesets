rule TTP_XOR_QUAD_CurrentVersionRun_37ad {
  strings:
    $key_37ad = { 64 c2 [2] 40 cc [2] 6b e0 [2] 45 c2 [2] 51 d9 [2] 5e c3 [2] 40 de [2] 42 df [2] 59 d9 [2] 45 de [2] 59 f1 }

  condition:
    any of them
}