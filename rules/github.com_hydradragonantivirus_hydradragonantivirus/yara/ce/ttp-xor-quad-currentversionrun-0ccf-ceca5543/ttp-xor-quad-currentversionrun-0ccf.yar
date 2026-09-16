rule TTP_XOR_QUAD_CurrentVersionRun_0ccf {
  strings:
    $key_0ccf = { 5f a0 [2] 7b ae [2] 50 82 [2] 7e a0 [2] 6a bb [2] 65 a1 [2] 7b bc [2] 79 bd [2] 62 bb [2] 7e bc [2] 62 93 }

  condition:
    any of them
}