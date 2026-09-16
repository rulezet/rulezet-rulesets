rule TTP_XOR_QUAD_CurrentVersionRun_0adc {
  strings:
    $key_0adc = { 59 b3 [2] 7d bd [2] 56 91 [2] 78 b3 [2] 6c a8 [2] 63 b2 [2] 7d af [2] 7f ae [2] 64 a8 [2] 78 af [2] 64 80 }

  condition:
    any of them
}