rule TTP_XOR_QUAD_CurrentVersionRun_e9bb {
  strings:
    $key_e9bb = { ba d4 [2] 9e da [2] b5 f6 [2] 9b d4 [2] 8f cf [2] 80 d5 [2] 9e c8 [2] 9c c9 [2] 87 cf [2] 9b c8 [2] 87 e7 }

  condition:
    any of them
}