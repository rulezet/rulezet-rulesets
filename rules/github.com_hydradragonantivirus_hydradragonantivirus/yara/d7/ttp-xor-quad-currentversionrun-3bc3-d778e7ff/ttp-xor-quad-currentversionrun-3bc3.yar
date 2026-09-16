rule TTP_XOR_QUAD_CurrentVersionRun_3bc3 {
  strings:
    $key_3bc3 = { 68 ac [2] 4c a2 [2] 67 8e [2] 49 ac [2] 5d b7 [2] 52 ad [2] 4c b0 [2] 4e b1 [2] 55 b7 [2] 49 b0 [2] 55 9f }

  condition:
    any of them
}