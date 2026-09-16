rule TTP_XOR_QUAD_CurrentVersionRun_06cf {
  strings:
    $key_06cf = { 55 a0 [2] 71 ae [2] 5a 82 [2] 74 a0 [2] 60 bb [2] 6f a1 [2] 71 bc [2] 73 bd [2] 68 bb [2] 74 bc [2] 68 93 }

  condition:
    any of them
}