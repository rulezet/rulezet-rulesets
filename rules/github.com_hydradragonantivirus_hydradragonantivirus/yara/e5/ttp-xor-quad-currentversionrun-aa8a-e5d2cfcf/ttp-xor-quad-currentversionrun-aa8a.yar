rule TTP_XOR_QUAD_CurrentVersionRun_aa8a {
  strings:
    $key_aa8a = { f9 e5 [2] dd eb [2] f6 c7 [2] d8 e5 [2] cc fe [2] c3 e4 [2] dd f9 [2] df f8 [2] c4 fe [2] d8 f9 [2] c4 d6 }

  condition:
    any of them
}