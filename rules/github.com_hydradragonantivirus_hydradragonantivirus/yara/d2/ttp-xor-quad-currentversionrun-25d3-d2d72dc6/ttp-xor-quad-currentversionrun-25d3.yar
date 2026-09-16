rule TTP_XOR_QUAD_CurrentVersionRun_25d3 {
  strings:
    $key_25d3 = { 76 bc [2] 52 b2 [2] 79 9e [2] 57 bc [2] 43 a7 [2] 4c bd [2] 52 a0 [2] 50 a1 [2] 4b a7 [2] 57 a0 [2] 4b 8f }

  condition:
    any of them
}