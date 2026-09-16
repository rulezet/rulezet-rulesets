rule TTP_XOR_QUAD_CurrentVersionRun_c6ae {
  strings:
    $key_c6ae = { 95 c1 [2] b1 cf [2] 9a e3 [2] b4 c1 [2] a0 da [2] af c0 [2] b1 dd [2] b3 dc [2] a8 da [2] b4 dd [2] a8 f2 }

  condition:
    any of them
}