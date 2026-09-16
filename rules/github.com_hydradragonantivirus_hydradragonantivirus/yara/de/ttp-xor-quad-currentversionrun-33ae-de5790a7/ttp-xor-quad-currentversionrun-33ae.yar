rule TTP_XOR_QUAD_CurrentVersionRun_33ae {
  strings:
    $key_33ae = { 60 c1 [2] 44 cf [2] 6f e3 [2] 41 c1 [2] 55 da [2] 5a c0 [2] 44 dd [2] 46 dc [2] 5d da [2] 41 dd [2] 5d f2 }

  condition:
    any of them
}