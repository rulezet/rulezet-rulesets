rule TTP_XOR_QUAD_CurrentVersionRun_8e8f {
  strings:
    $key_8e8f = { dd e0 [2] f9 ee [2] d2 c2 [2] fc e0 [2] e8 fb [2] e7 e1 [2] f9 fc [2] fb fd [2] e0 fb [2] fc fc [2] e0 d3 }

  condition:
    any of them
}