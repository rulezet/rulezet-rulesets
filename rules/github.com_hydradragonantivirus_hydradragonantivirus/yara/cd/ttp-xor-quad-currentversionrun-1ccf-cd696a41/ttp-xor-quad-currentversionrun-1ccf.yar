rule TTP_XOR_QUAD_CurrentVersionRun_1ccf {
  strings:
    $key_1ccf = { 4f a0 [2] 6b ae [2] 40 82 [2] 6e a0 [2] 7a bb [2] 75 a1 [2] 6b bc [2] 69 bd [2] 72 bb [2] 6e bc [2] 72 93 }

  condition:
    any of them
}