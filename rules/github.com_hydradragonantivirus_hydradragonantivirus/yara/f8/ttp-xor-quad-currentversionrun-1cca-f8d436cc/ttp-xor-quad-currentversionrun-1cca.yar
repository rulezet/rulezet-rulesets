rule TTP_XOR_QUAD_CurrentVersionRun_1cca {
  strings:
    $key_1cca = { 4f a5 [2] 6b ab [2] 40 87 [2] 6e a5 [2] 7a be [2] 75 a4 [2] 6b b9 [2] 69 b8 [2] 72 be [2] 6e b9 [2] 72 96 }

  condition:
    any of them
}