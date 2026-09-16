rule TTP_XOR_QUAD_CurrentVersionRun_d5ae {
  strings:
    $key_d5ae = { 86 c1 [2] a2 cf [2] 89 e3 [2] a7 c1 [2] b3 da [2] bc c0 [2] a2 dd [2] a0 dc [2] bb da [2] a7 dd [2] bb f2 }

  condition:
    any of them
}