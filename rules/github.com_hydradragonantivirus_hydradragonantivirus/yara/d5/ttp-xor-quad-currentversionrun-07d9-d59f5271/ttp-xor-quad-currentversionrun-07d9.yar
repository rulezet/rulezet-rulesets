rule TTP_XOR_QUAD_CurrentVersionRun_07d9 {
  strings:
    $key_07d9 = { 54 b6 [2] 70 b8 [2] 5b 94 [2] 75 b6 [2] 61 ad [2] 6e b7 [2] 70 aa [2] 72 ab [2] 69 ad [2] 75 aa [2] 69 85 }

  condition:
    any of them
}