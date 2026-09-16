rule TTP_XOR_QUAD_CurrentVersionRun_24bb {
  strings:
    $key_24bb = { 77 d4 [2] 53 da [2] 78 f6 [2] 56 d4 [2] 42 cf [2] 4d d5 [2] 53 c8 [2] 51 c9 [2] 4a cf [2] 56 c8 [2] 4a e7 }

  condition:
    any of them
}