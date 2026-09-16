rule TTP_XOR_QUAD_CurrentVersionRun_a7e7 {
  strings:
    $key_a7e7 = { f4 88 [2] d0 86 [2] fb aa [2] d5 88 [2] c1 93 [2] ce 89 [2] d0 94 [2] d2 95 [2] c9 93 [2] d5 94 [2] c9 bb }

  condition:
    any of them
}