rule TTP_XOR_QUAD_CurrentVersionRun_4dbb {
  strings:
    $key_4dbb = { 1e d4 [2] 3a da [2] 11 f6 [2] 3f d4 [2] 2b cf [2] 24 d5 [2] 3a c8 [2] 38 c9 [2] 23 cf [2] 3f c8 [2] 23 e7 }

  condition:
    any of them
}