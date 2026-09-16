rule TTP_XOR_QUAD_CurrentVersionRun_d4ae {
  strings:
    $key_d4ae = { 87 c1 [2] a3 cf [2] 88 e3 [2] a6 c1 [2] b2 da [2] bd c0 [2] a3 dd [2] a1 dc [2] ba da [2] a6 dd [2] ba f2 }

  condition:
    any of them
}