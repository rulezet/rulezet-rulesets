rule TTP_XOR_QUAD_CurrentVersionRun_e6ae {
  strings:
    $key_e6ae = { b5 c1 [2] 91 cf [2] ba e3 [2] 94 c1 [2] 80 da [2] 8f c0 [2] 91 dd [2] 93 dc [2] 88 da [2] 94 dd [2] 88 f2 }

  condition:
    any of them
}