rule TTP_XOR_QUAD_CurrentVersionRun_50ae {
  strings:
    $key_50ae = { 03 c1 [2] 27 cf [2] 0c e3 [2] 22 c1 [2] 36 da [2] 39 c0 [2] 27 dd [2] 25 dc [2] 3e da [2] 22 dd [2] 3e f2 }

  condition:
    any of them
}