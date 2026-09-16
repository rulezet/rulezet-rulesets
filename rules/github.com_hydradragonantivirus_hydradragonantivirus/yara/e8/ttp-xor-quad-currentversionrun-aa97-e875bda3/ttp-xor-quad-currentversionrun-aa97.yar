rule TTP_XOR_QUAD_CurrentVersionRun_aa97 {
  strings:
    $key_aa97 = { f9 f8 [2] dd f6 [2] f6 da [2] d8 f8 [2] cc e3 [2] c3 f9 [2] dd e4 [2] df e5 [2] c4 e3 [2] d8 e4 [2] c4 cb }

  condition:
    any of them
}