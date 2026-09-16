rule TTP_XOR_QUAD_CurrentVersionRun_5bc4 {
  strings:
    $key_5bc4 = { 08 ab [2] 2c a5 [2] 07 89 [2] 29 ab [2] 3d b0 [2] 32 aa [2] 2c b7 [2] 2e b6 [2] 35 b0 [2] 29 b7 [2] 35 98 }

  condition:
    any of them
}