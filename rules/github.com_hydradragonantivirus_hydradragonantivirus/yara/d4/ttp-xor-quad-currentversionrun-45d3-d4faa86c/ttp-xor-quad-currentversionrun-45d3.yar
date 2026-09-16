rule TTP_XOR_QUAD_CurrentVersionRun_45d3 {
  strings:
    $key_45d3 = { 16 bc [2] 32 b2 [2] 19 9e [2] 37 bc [2] 23 a7 [2] 2c bd [2] 32 a0 [2] 30 a1 [2] 2b a7 [2] 37 a0 [2] 2b 8f }

  condition:
    any of them
}