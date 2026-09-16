rule TTP_XOR_QUAD_CurrentVersionRun_9a8f {
  strings:
    $key_9a8f = { c9 e0 [2] ed ee [2] c6 c2 [2] e8 e0 [2] fc fb [2] f3 e1 [2] ed fc [2] ef fd [2] f4 fb [2] e8 fc [2] f4 d3 }

  condition:
    any of them
}