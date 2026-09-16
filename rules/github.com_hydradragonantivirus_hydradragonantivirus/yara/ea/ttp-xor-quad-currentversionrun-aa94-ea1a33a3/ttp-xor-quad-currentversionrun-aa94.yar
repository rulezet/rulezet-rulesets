rule TTP_XOR_QUAD_CurrentVersionRun_aa94 {
  strings:
    $key_aa94 = { f9 fb [2] dd f5 [2] f6 d9 [2] d8 fb [2] cc e0 [2] c3 fa [2] dd e7 [2] df e6 [2] c4 e0 [2] d8 e7 [2] c4 c8 }

  condition:
    any of them
}