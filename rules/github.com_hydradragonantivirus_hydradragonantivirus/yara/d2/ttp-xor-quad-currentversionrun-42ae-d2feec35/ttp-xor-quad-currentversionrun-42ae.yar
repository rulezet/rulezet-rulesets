rule TTP_XOR_QUAD_CurrentVersionRun_42ae {
  strings:
    $key_42ae = { 11 c1 [2] 35 cf [2] 1e e3 [2] 30 c1 [2] 24 da [2] 2b c0 [2] 35 dd [2] 37 dc [2] 2c da [2] 30 dd [2] 2c f2 }

  condition:
    any of them
}