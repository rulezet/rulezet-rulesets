rule TTP_XOR_QUAD_CurrentVersionRun_1bc5 {
  strings:
    $key_1bc5 = { 48 aa [2] 6c a4 [2] 47 88 [2] 69 aa [2] 7d b1 [2] 72 ab [2] 6c b6 [2] 6e b7 [2] 75 b1 [2] 69 b6 [2] 75 99 }

  condition:
    any of them
}