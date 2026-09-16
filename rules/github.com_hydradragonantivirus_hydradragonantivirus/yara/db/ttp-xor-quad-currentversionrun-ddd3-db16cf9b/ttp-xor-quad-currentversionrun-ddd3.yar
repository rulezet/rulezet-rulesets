rule TTP_XOR_QUAD_CurrentVersionRun_ddd3 {
  strings:
    $key_ddd3 = { 8e bc [2] aa b2 [2] 81 9e [2] af bc [2] bb a7 [2] b4 bd [2] aa a0 [2] a8 a1 [2] b3 a7 [2] af a0 [2] b3 8f }

  condition:
    any of them
}