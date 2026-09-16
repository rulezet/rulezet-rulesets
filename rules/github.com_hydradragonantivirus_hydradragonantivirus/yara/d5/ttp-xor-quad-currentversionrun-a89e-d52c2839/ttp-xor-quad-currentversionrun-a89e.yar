rule TTP_XOR_QUAD_CurrentVersionRun_a89e {
  strings:
    $key_a89e = { fb f1 [2] df ff [2] f4 d3 [2] da f1 [2] ce ea [2] c1 f0 [2] df ed [2] dd ec [2] c6 ea [2] da ed [2] c6 c2 }

  condition:
    any of them
}