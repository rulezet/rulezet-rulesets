rule TTP_XOR_QUAD_CurrentVersionRun_1bc4 {
  strings:
    $key_1bc4 = { 48 ab [2] 6c a5 [2] 47 89 [2] 69 ab [2] 7d b0 [2] 72 aa [2] 6c b7 [2] 6e b6 [2] 75 b0 [2] 69 b7 [2] 75 98 }

  condition:
    any of them
}