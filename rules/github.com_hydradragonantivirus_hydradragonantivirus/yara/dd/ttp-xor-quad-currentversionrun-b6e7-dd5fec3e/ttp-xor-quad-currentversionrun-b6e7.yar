rule TTP_XOR_QUAD_CurrentVersionRun_b6e7 {
  strings:
    $key_b6e7 = { e5 88 [2] c1 86 [2] ea aa [2] c4 88 [2] d0 93 [2] df 89 [2] c1 94 [2] c3 95 [2] d8 93 [2] c4 94 [2] d8 bb }

  condition:
    any of them
}