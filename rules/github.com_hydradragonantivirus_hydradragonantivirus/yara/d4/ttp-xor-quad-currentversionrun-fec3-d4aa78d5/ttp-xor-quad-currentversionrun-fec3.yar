rule TTP_XOR_QUAD_CurrentVersionRun_fec3 {
  strings:
    $key_fec3 = { ad ac [2] 89 a2 [2] a2 8e [2] 8c ac [2] 98 b7 [2] 97 ad [2] 89 b0 [2] 8b b1 [2] 90 b7 [2] 8c b0 [2] 90 9f }

  condition:
    any of them
}