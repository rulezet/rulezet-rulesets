rule TTP_XOR_QUAD_CurrentVersionRun_978f {
  strings:
    $key_978f = { c4 e0 [2] e0 ee [2] cb c2 [2] e5 e0 [2] f1 fb [2] fe e1 [2] e0 fc [2] e2 fd [2] f9 fb [2] e5 fc [2] f9 d3 }

  condition:
    any of them
}