rule TTP_XOR_QUAD_CurrentVersionRun_f9c5 {
  strings:
    $key_f9c5 = { aa aa [2] 8e a4 [2] a5 88 [2] 8b aa [2] 9f b1 [2] 90 ab [2] 8e b6 [2] 8c b7 [2] 97 b1 [2] 8b b6 [2] 97 99 }

  condition:
    any of them
}