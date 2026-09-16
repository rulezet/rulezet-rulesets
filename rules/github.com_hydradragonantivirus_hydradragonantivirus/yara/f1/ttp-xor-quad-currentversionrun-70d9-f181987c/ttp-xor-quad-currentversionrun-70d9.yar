rule TTP_XOR_QUAD_CurrentVersionRun_70d9 {
  strings:
    $key_70d9 = { 23 b6 [2] 07 b8 [2] 2c 94 [2] 02 b6 [2] 16 ad [2] 19 b7 [2] 07 aa [2] 05 ab [2] 1e ad [2] 02 aa [2] 1e 85 }

  condition:
    any of them
}