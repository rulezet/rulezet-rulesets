rule TTP_XOR_QUAD_CurrentVersionRun_aa83 {
  strings:
    $key_aa83 = { f9 ec [2] dd e2 [2] f6 ce [2] d8 ec [2] cc f7 [2] c3 ed [2] dd f0 [2] df f1 [2] c4 f7 [2] d8 f0 [2] c4 df }

  condition:
    any of them
}