rule TTP_XOR_QUAD_CurrentVersionRun_3ac4 {
  strings:
    $key_3ac4 = { 69 ab [2] 4d a5 [2] 66 89 [2] 48 ab [2] 5c b0 [2] 53 aa [2] 4d b7 [2] 4f b6 [2] 54 b0 [2] 48 b7 [2] 54 98 }

  condition:
    any of them
}