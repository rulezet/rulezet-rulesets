rule TTP_XOR_QUAD_CurrentVersionRun_61bb {
  strings:
    $key_61bb = { 32 d4 [2] 16 da [2] 3d f6 [2] 13 d4 [2] 07 cf [2] 08 d5 [2] 16 c8 [2] 14 c9 [2] 0f cf [2] 13 c8 [2] 0f e7 }

  condition:
    any of them
}