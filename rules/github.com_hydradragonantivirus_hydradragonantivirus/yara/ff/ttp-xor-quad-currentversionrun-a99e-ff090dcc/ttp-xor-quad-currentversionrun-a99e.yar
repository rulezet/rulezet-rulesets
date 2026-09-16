rule TTP_XOR_QUAD_CurrentVersionRun_a99e {
  strings:
    $key_a99e = { fa f1 [2] de ff [2] f5 d3 [2] db f1 [2] cf ea [2] c0 f0 [2] de ed [2] dc ec [2] c7 ea [2] db ed [2] c7 c2 }

  condition:
    any of them
}