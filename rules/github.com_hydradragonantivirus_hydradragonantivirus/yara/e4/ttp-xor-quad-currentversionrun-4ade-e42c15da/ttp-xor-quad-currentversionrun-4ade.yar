rule TTP_XOR_QUAD_CurrentVersionRun_4ade {
  strings:
    $key_4ade = { 19 b1 [2] 3d bf [2] 16 93 [2] 38 b1 [2] 2c aa [2] 23 b0 [2] 3d ad [2] 3f ac [2] 24 aa [2] 38 ad [2] 24 82 }

  condition:
    any of them
}