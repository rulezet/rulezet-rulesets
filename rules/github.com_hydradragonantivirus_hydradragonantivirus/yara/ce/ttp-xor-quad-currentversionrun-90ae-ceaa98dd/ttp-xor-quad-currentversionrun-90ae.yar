rule TTP_XOR_QUAD_CurrentVersionRun_90ae {
  strings:
    $key_90ae = { c3 c1 [2] e7 cf [2] cc e3 [2] e2 c1 [2] f6 da [2] f9 c0 [2] e7 dd [2] e5 dc [2] fe da [2] e2 dd [2] fe f2 }

  condition:
    any of them
}