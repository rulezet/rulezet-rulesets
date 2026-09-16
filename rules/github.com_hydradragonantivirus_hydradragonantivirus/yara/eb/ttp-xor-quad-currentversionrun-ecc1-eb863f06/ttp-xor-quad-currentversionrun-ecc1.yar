rule TTP_XOR_QUAD_CurrentVersionRun_ecc1 {
  strings:
    $key_ecc1 = { bf ae [2] 9b a0 [2] b0 8c [2] 9e ae [2] 8a b5 [2] 85 af [2] 9b b2 [2] 99 b3 [2] 82 b5 [2] 9e b2 [2] 82 9d }

  condition:
    any of them
}