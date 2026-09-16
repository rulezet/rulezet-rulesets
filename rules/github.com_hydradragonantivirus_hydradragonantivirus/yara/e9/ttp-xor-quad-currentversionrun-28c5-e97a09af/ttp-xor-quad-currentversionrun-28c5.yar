rule TTP_XOR_QUAD_CurrentVersionRun_28c5 {
  strings:
    $key_28c5 = { 7b aa [2] 5f a4 [2] 74 88 [2] 5a aa [2] 4e b1 [2] 41 ab [2] 5f b6 [2] 5d b7 [2] 46 b1 [2] 5a b6 [2] 46 99 }

  condition:
    any of them
}