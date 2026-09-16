rule TTP_XOR_QUAD_CurrentVersionRun_a7cf {
  strings:
    $key_a7cf = { f4 a0 [2] d0 ae [2] fb 82 [2] d5 a0 [2] c1 bb [2] ce a1 [2] d0 bc [2] d2 bd [2] c9 bb [2] d5 bc [2] c9 93 }

  condition:
    any of them
}