rule TTP_XOR_QUAD_CurrentVersionRun_29d9 {
  strings:
    $key_29d9 = { 7a b6 [2] 5e b8 [2] 75 94 [2] 5b b6 [2] 4f ad [2] 40 b7 [2] 5e aa [2] 5c ab [2] 47 ad [2] 5b aa [2] 47 85 }

  condition:
    any of them
}