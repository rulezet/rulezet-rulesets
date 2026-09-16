rule TTP_XOR_QUAD_CurrentVersionRun_c9bb {
  strings:
    $key_c9bb = { 9a d4 [2] be da [2] 95 f6 [2] bb d4 [2] af cf [2] a0 d5 [2] be c8 [2] bc c9 [2] a7 cf [2] bb c8 [2] a7 e7 }

  condition:
    any of them
}