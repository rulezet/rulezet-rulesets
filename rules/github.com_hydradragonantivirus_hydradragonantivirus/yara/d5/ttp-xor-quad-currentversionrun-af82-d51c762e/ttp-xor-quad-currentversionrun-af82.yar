rule TTP_XOR_QUAD_CurrentVersionRun_af82 {
  strings:
    $key_af82 = { fc ed [2] d8 e3 [2] f3 cf [2] dd ed [2] c9 f6 [2] c6 ec [2] d8 f1 [2] da f0 [2] c1 f6 [2] dd f1 [2] c1 de }

  condition:
    any of them
}