rule TTP_XOR_QUAD_CurrentVersionRun_a3c2 {
  strings:
    $key_a3c2 = { f0 ad [2] d4 a3 [2] ff 8f [2] d1 ad [2] c5 b6 [2] ca ac [2] d4 b1 [2] d6 b0 [2] cd b6 [2] d1 b1 [2] cd 9e }

  condition:
    any of them
}