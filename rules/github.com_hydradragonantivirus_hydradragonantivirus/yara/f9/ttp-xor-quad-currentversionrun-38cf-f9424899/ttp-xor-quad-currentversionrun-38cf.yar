rule TTP_XOR_QUAD_CurrentVersionRun_38cf {
  strings:
    $key_38cf = { 6b a0 [2] 4f ae [2] 64 82 [2] 4a a0 [2] 5e bb [2] 51 a1 [2] 4f bc [2] 4d bd [2] 56 bb [2] 4a bc [2] 56 93 }

  condition:
    any of them
}