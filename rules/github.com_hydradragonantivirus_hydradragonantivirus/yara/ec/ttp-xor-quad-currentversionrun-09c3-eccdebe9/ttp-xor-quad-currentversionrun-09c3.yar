rule TTP_XOR_QUAD_CurrentVersionRun_09c3 {
  strings:
    $key_09c3 = { 5a ac [2] 7e a2 [2] 55 8e [2] 7b ac [2] 6f b7 [2] 60 ad [2] 7e b0 [2] 7c b1 [2] 67 b7 [2] 7b b0 [2] 67 9f }

  condition:
    any of them
}