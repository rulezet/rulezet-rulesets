rule TTP_XOR_QUAD_CurrentVersionRun_a7c4 {
  strings:
    $key_a7c4 = { f4 ab [2] d0 a5 [2] fb 89 [2] d5 ab [2] c1 b0 [2] ce aa [2] d0 b7 [2] d2 b6 [2] c9 b0 [2] d5 b7 [2] c9 98 }

  condition:
    any of them
}