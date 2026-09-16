rule TTP_XOR_QUAD_CurrentVersionRun_a882 {
  strings:
    $key_a882 = { fb ed [2] df e3 [2] f4 cf [2] da ed [2] ce f6 [2] c1 ec [2] df f1 [2] dd f0 [2] c6 f6 [2] da f1 [2] c6 de }

  condition:
    any of them
}