rule TTP_XOR_QUAD_CurrentVersionRun_aa8f {
  strings:
    $key_aa8f = { f9 e0 [2] dd ee [2] f6 c2 [2] d8 e0 [2] cc fb [2] c3 e1 [2] dd fc [2] df fd [2] c4 fb [2] d8 fc [2] c4 d3 }

  condition:
    any of them
}