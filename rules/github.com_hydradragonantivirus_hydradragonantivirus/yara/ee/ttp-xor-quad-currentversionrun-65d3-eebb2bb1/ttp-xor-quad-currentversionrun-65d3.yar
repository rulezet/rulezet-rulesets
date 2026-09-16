rule TTP_XOR_QUAD_CurrentVersionRun_65d3 {
  strings:
    $key_65d3 = { 36 bc [2] 12 b2 [2] 39 9e [2] 17 bc [2] 03 a7 [2] 0c bd [2] 12 a0 [2] 10 a1 [2] 0b a7 [2] 17 a0 [2] 0b 8f }

  condition:
    any of them
}