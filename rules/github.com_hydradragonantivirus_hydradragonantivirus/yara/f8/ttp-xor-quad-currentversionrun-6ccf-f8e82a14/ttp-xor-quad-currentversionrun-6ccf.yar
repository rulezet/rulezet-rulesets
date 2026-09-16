rule TTP_XOR_QUAD_CurrentVersionRun_6ccf {
  strings:
    $key_6ccf = { 3f a0 [2] 1b ae [2] 30 82 [2] 1e a0 [2] 0a bb [2] 05 a1 [2] 1b bc [2] 19 bd [2] 02 bb [2] 1e bc [2] 02 93 }

  condition:
    any of them
}