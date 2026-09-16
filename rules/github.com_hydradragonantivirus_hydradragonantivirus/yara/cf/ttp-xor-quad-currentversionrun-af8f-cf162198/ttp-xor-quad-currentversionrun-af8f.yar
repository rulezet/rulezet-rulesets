rule TTP_XOR_QUAD_CurrentVersionRun_af8f {
  strings:
    $key_af8f = { fc e0 [2] d8 ee [2] f3 c2 [2] dd e0 [2] c9 fb [2] c6 e1 [2] d8 fc [2] da fd [2] c1 fb [2] dd fc [2] c1 d3 }

  condition:
    any of them
}