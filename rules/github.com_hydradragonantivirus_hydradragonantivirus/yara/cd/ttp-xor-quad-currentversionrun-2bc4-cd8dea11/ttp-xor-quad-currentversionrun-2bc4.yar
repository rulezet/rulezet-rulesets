rule TTP_XOR_QUAD_CurrentVersionRun_2bc4 {
  strings:
    $key_2bc4 = { 78 ab [2] 5c a5 [2] 77 89 [2] 59 ab [2] 4d b0 [2] 42 aa [2] 5c b7 [2] 5e b6 [2] 45 b0 [2] 59 b7 [2] 45 98 }

  condition:
    any of them
}