rule TTP_XOR_QUAD_CurrentVersionRun_6cc3 {
  strings:
    $key_6cc3 = { 3f ac [2] 1b a2 [2] 30 8e [2] 1e ac [2] 0a b7 [2] 05 ad [2] 1b b0 [2] 19 b1 [2] 02 b7 [2] 1e b0 [2] 02 9f }

  condition:
    any of them
}