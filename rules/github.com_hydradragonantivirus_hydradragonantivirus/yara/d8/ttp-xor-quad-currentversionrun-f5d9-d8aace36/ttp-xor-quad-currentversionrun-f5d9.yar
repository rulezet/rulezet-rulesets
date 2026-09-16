rule TTP_XOR_QUAD_CurrentVersionRun_f5d9 {
  strings:
    $key_f5d9 = { a6 b6 [2] 82 b8 [2] a9 94 [2] 87 b6 [2] 93 ad [2] 9c b7 [2] 82 aa [2] 80 ab [2] 9b ad [2] 87 aa [2] 9b 85 }

  condition:
    any of them
}