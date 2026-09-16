rule TTP_XOR_QUAD_CurrentVersionRun_5dca {
  strings:
    $key_5dca = { 0e a5 [2] 2a ab [2] 01 87 [2] 2f a5 [2] 3b be [2] 34 a4 [2] 2a b9 [2] 28 b8 [2] 33 be [2] 2f b9 [2] 33 96 }

  condition:
    any of them
}