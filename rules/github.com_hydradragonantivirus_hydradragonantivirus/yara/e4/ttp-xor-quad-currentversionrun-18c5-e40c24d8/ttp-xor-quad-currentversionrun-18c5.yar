rule TTP_XOR_QUAD_CurrentVersionRun_18c5 {
  strings:
    $key_18c5 = { 4b aa [2] 6f a4 [2] 44 88 [2] 6a aa [2] 7e b1 [2] 71 ab [2] 6f b6 [2] 6d b7 [2] 76 b1 [2] 6a b6 [2] 76 99 }

  condition:
    any of them
}