rule TTP_XOR_QUAD_CurrentVersionRun_76bc {
  strings:
    $key_76bc = { 25 d3 [2] 01 dd [2] 2a f1 [2] 04 d3 [2] 10 c8 [2] 1f d2 [2] 01 cf [2] 03 ce [2] 18 c8 [2] 04 cf [2] 18 e0 }

  condition:
    any of them
}