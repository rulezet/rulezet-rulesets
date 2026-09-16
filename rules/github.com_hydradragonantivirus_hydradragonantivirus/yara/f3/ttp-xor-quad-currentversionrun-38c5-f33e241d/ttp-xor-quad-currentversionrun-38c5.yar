rule TTP_XOR_QUAD_CurrentVersionRun_38c5 {
  strings:
    $key_38c5 = { 6b aa [2] 4f a4 [2] 64 88 [2] 4a aa [2] 5e b1 [2] 51 ab [2] 4f b6 [2] 4d b7 [2] 56 b1 [2] 4a b6 [2] 56 99 }

  condition:
    any of them
}