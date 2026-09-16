rule TTP_XOR_QUAD_CurrentVersionRun_a7a9 {
  strings:
    $key_a7a9 = { f4 c6 [2] d0 c8 [2] fb e4 [2] d5 c6 [2] c1 dd [2] ce c7 [2] d0 da [2] d2 db [2] c9 dd [2] d5 da [2] c9 f5 }

  condition:
    any of them
}