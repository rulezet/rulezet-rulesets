rule TTP_XOR_QUAD_CurrentVersionRun_bb83 {
  strings:
    $key_bb83 = { e8 ec [2] cc e2 [2] e7 ce [2] c9 ec [2] dd f7 [2] d2 ed [2] cc f0 [2] ce f1 [2] d5 f7 [2] c9 f0 [2] d5 df }

  condition:
    any of them
}