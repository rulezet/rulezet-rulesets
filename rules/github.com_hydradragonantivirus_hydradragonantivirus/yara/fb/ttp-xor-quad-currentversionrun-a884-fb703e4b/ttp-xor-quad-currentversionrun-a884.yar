rule TTP_XOR_QUAD_CurrentVersionRun_a884 {
  strings:
    $key_a884 = { fb eb [2] df e5 [2] f4 c9 [2] da eb [2] ce f0 [2] c1 ea [2] df f7 [2] dd f6 [2] c6 f0 [2] da f7 [2] c6 d8 }

  condition:
    any of them
}