rule TTP_XOR_QUAD_CurrentVersionRun_a6a9 {
  strings:
    $key_a6a9 = { f5 c6 [2] d1 c8 [2] fa e4 [2] d4 c6 [2] c0 dd [2] cf c7 [2] d1 da [2] d3 db [2] c8 dd [2] d4 da [2] c8 f5 }

  condition:
    any of them
}