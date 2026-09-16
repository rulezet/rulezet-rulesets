rule TTP_XOR_QUAD_CurrentVersionRun_3dbd {
  strings:
    $key_3dbd = { 6e d2 [2] 4a dc [2] 61 f0 [2] 4f d2 [2] 5b c9 [2] 54 d3 [2] 4a ce [2] 48 cf [2] 53 c9 [2] 4f ce [2] 53 e1 }

  condition:
    any of them
}