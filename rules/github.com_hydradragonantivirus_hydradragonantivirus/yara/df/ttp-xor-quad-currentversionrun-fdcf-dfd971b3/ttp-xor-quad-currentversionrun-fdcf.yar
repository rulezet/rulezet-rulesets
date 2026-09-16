rule TTP_XOR_QUAD_CurrentVersionRun_fdcf {
  strings:
    $key_fdcf = { ae a0 [2] 8a ae [2] a1 82 [2] 8f a0 [2] 9b bb [2] 94 a1 [2] 8a bc [2] 88 bd [2] 93 bb [2] 8f bc [2] 93 93 }

  condition:
    any of them
}