rule TTP_XOR_QUAD_CurrentVersionRun_7ac4 {
  strings:
    $key_7ac4 = { 29 ab [2] 0d a5 [2] 26 89 [2] 08 ab [2] 1c b0 [2] 13 aa [2] 0d b7 [2] 0f b6 [2] 14 b0 [2] 08 b7 [2] 14 98 }

  condition:
    any of them
}