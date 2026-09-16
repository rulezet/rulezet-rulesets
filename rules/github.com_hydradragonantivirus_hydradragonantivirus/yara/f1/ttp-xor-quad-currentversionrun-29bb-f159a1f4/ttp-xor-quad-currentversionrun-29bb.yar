rule TTP_XOR_QUAD_CurrentVersionRun_29bb {
  strings:
    $key_29bb = { 7a d4 [2] 5e da [2] 75 f6 [2] 5b d4 [2] 4f cf [2] 40 d5 [2] 5e c8 [2] 5c c9 [2] 47 cf [2] 5b c8 [2] 47 e7 }

  condition:
    any of them
}