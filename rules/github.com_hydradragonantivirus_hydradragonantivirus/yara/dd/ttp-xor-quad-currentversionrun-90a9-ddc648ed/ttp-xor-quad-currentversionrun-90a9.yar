rule TTP_XOR_QUAD_CurrentVersionRun_90a9 {
  strings:
    $key_90a9 = { c3 c6 [2] e7 c8 [2] cc e4 [2] e2 c6 [2] f6 dd [2] f9 c7 [2] e7 da [2] e5 db [2] fe dd [2] e2 da [2] fe f5 }

  condition:
    any of them
}