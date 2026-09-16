rule TTP_XOR_QUAD_CurrentVersionRun_1cc3 {
  strings:
    $key_1cc3 = { 4f ac [2] 6b a2 [2] 40 8e [2] 6e ac [2] 7a b7 [2] 75 ad [2] 6b b0 [2] 69 b1 [2] 72 b7 [2] 6e b0 [2] 72 9f }

  condition:
    any of them
}