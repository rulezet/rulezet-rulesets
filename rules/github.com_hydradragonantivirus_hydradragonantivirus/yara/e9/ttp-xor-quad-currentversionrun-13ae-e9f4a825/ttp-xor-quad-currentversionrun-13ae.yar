rule TTP_XOR_QUAD_CurrentVersionRun_13ae {
  strings:
    $key_13ae = { 40 c1 [2] 64 cf [2] 4f e3 [2] 61 c1 [2] 75 da [2] 7a c0 [2] 64 dd [2] 66 dc [2] 7d da [2] 61 dd [2] 7d f2 }

  condition:
    any of them
}