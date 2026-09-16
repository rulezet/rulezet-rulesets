rule TTP_XOR_QUAD_CurrentVersionRun_d5bc {
  strings:
    $key_d5bc = { 86 d3 [2] a2 dd [2] 89 f1 [2] a7 d3 [2] b3 c8 [2] bc d2 [2] a2 cf [2] a0 ce [2] bb c8 [2] a7 cf [2] bb e0 }

  condition:
    any of them
}