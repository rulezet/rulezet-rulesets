rule TTP_XOR_QUAD_CurrentVersionRun_d3ae {
  strings:
    $key_d3ae = { 80 c1 [2] a4 cf [2] 8f e3 [2] a1 c1 [2] b5 da [2] ba c0 [2] a4 dd [2] a6 dc [2] bd da [2] a1 dd [2] bd f2 }

  condition:
    any of them
}