rule TTP_XOR_QUAD_CurrentVersionRun_0cc5 {
  strings:
    $key_0cc5 = { 5f aa [2] 7b a4 [2] 50 88 [2] 7e aa [2] 6a b1 [2] 65 ab [2] 7b b6 [2] 79 b7 [2] 62 b1 [2] 7e b6 [2] 62 99 }

  condition:
    any of them
}