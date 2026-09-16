rule TTP_XOR_QUAD_CurrentVersionRun_79d9 {
  strings:
    $key_79d9 = { 2a b6 [2] 0e b8 [2] 25 94 [2] 0b b6 [2] 1f ad [2] 10 b7 [2] 0e aa [2] 0c ab [2] 17 ad [2] 0b aa [2] 17 85 }

  condition:
    any of them
}