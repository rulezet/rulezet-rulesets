rule TTP_XOR_QUAD_CurrentVersionRun_09bb {
  strings:
    $key_09bb = { 5a d4 [2] 7e da [2] 55 f6 [2] 7b d4 [2] 6f cf [2] 60 d5 [2] 7e c8 [2] 7c c9 [2] 67 cf [2] 7b c8 [2] 67 e7 }

  condition:
    any of them
}