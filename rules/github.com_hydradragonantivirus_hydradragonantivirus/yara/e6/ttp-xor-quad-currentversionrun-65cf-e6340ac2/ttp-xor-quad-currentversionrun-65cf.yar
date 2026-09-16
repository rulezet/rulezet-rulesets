rule TTP_XOR_QUAD_CurrentVersionRun_65cf {
  strings:
    $key_65cf = { 36 a0 [2] 12 ae [2] 39 82 [2] 17 a0 [2] 03 bb [2] 0c a1 [2] 12 bc [2] 10 bd [2] 0b bb [2] 17 bc [2] 0b 93 }

  condition:
    any of them
}