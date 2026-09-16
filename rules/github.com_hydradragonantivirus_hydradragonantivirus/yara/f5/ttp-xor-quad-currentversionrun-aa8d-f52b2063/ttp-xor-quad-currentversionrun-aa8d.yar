rule TTP_XOR_QUAD_CurrentVersionRun_aa8d {
  strings:
    $key_aa8d = { f9 e2 [2] dd ec [2] f6 c0 [2] d8 e2 [2] cc f9 [2] c3 e3 [2] dd fe [2] df ff [2] c4 f9 [2] d8 fe [2] c4 d1 }

  condition:
    any of them
}