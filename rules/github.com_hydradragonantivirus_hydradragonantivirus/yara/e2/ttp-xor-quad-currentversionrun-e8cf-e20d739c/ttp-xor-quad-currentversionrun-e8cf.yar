rule TTP_XOR_QUAD_CurrentVersionRun_e8cf {
  strings:
    $key_e8cf = { bb a0 [2] 9f ae [2] b4 82 [2] 9a a0 [2] 8e bb [2] 81 a1 [2] 9f bc [2] 9d bd [2] 86 bb [2] 9a bc [2] 86 93 }

  condition:
    any of them
}