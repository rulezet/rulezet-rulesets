rule TTP_XOR_QUAD_CurrentVersionRun_ad8f {
  strings:
    $key_ad8f = { fe e0 [2] da ee [2] f1 c2 [2] df e0 [2] cb fb [2] c4 e1 [2] da fc [2] d8 fd [2] c3 fb [2] df fc [2] c3 d3 }

  condition:
    any of them
}