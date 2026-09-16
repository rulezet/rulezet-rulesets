rule TTP_XOR_QUAD_CurrentVersionRun_39c3 {
  strings:
    $key_39c3 = { 6a ac [2] 4e a2 [2] 65 8e [2] 4b ac [2] 5f b7 [2] 50 ad [2] 4e b0 [2] 4c b1 [2] 57 b7 [2] 4b b0 [2] 57 9f }

  condition:
    any of them
}