rule TTP_XOR_QUAD_CurrentVersionRun_d7ae {
  strings:
    $key_d7ae = { 84 c1 [2] a0 cf [2] 8b e3 [2] a5 c1 [2] b1 da [2] be c0 [2] a0 dd [2] a2 dc [2] b9 da [2] a5 dd [2] b9 f2 }

  condition:
    any of them
}