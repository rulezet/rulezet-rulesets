rule TTP_XOR_QUAD_CurrentVersionRun_11bb {
  strings:
    $key_11bb = { 42 d4 [2] 66 da [2] 4d f6 [2] 63 d4 [2] 77 cf [2] 78 d5 [2] 66 c8 [2] 64 c9 [2] 7f cf [2] 63 c8 [2] 7f e7 }

  condition:
    any of them
}