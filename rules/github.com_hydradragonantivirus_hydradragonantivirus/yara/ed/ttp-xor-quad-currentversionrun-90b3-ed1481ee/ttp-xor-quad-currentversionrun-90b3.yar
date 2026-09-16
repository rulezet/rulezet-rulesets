rule TTP_XOR_QUAD_CurrentVersionRun_90b3 {
  strings:
    $key_90b3 = { c3 dc [2] e7 d2 [2] cc fe [2] e2 dc [2] f6 c7 [2] f9 dd [2] e7 c0 [2] e5 c1 [2] fe c7 [2] e2 c0 [2] fe ef }

  condition:
    any of them
}