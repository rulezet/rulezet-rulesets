rule TTP_XOR_QUAD_CurrentVersionRun_fccf {
  strings:
    $key_fccf = { af a0 [2] 8b ae [2] a0 82 [2] 8e a0 [2] 9a bb [2] 95 a1 [2] 8b bc [2] 89 bd [2] 92 bb [2] 8e bc [2] 92 93 }

  condition:
    any of them
}