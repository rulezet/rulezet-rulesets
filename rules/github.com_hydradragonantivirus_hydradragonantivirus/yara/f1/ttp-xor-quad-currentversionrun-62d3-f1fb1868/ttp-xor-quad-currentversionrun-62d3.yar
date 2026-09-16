rule TTP_XOR_QUAD_CurrentVersionRun_62d3 {
  strings:
    $key_62d3 = { 31 bc [2] 15 b2 [2] 3e 9e [2] 10 bc [2] 04 a7 [2] 0b bd [2] 15 a0 [2] 17 a1 [2] 0c a7 [2] 10 a0 [2] 0c 8f }

  condition:
    any of them
}