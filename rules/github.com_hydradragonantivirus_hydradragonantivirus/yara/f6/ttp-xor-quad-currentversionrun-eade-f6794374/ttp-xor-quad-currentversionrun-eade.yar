rule TTP_XOR_QUAD_CurrentVersionRun_eade {
  strings:
    $key_eade = { b9 b1 [2] 9d bf [2] b6 93 [2] 98 b1 [2] 8c aa [2] 83 b0 [2] 9d ad [2] 9f ac [2] 84 aa [2] 98 ad [2] 84 82 }

  condition:
    any of them
}