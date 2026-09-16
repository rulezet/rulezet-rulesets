rule TTP_XOR_QUAD_CurrentVersionRun_3dbb {
  strings:
    $key_3dbb = { 6e d4 [2] 4a da [2] 61 f6 [2] 4f d4 [2] 5b cf [2] 54 d5 [2] 4a c8 [2] 48 c9 [2] 53 cf [2] 4f c8 [2] 53 e7 }

  condition:
    any of them
}