rule TTP_XOR_QUAD_CurrentVersionRun_61d3 {
  strings:
    $key_61d3 = { 32 bc [2] 16 b2 [2] 3d 9e [2] 13 bc [2] 07 a7 [2] 08 bd [2] 16 a0 [2] 14 a1 [2] 0f a7 [2] 13 a0 [2] 0f 8f }

  condition:
    any of them
}