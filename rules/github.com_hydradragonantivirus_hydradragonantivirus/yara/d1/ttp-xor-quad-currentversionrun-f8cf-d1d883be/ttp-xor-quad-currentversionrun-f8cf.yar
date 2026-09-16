rule TTP_XOR_QUAD_CurrentVersionRun_f8cf {
  strings:
    $key_f8cf = { ab a0 [2] 8f ae [2] a4 82 [2] 8a a0 [2] 9e bb [2] 91 a1 [2] 8f bc [2] 8d bd [2] 96 bb [2] 8a bc [2] 96 93 }

  condition:
    any of them
}