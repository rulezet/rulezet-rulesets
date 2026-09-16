rule TTP_XOR_QUAD_CurrentVersionRun_09c5 {
  strings:
    $key_09c5 = { 5a aa [2] 7e a4 [2] 55 88 [2] 7b aa [2] 6f b1 [2] 60 ab [2] 7e b6 [2] 7c b7 [2] 67 b1 [2] 7b b6 [2] 67 99 }

  condition:
    any of them
}