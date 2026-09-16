rule TTP_XOR_QUAD_CurrentVersionRun_68cf {
  strings:
    $key_68cf = { 3b a0 [2] 1f ae [2] 34 82 [2] 1a a0 [2] 0e bb [2] 01 a1 [2] 1f bc [2] 1d bd [2] 06 bb [2] 1a bc [2] 06 93 }

  condition:
    any of them
}