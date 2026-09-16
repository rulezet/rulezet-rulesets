rule TTP_XOR_QUAD_CurrentVersionRun_67d9 {
  strings:
    $key_67d9 = { 34 b6 [2] 10 b8 [2] 3b 94 [2] 15 b6 [2] 01 ad [2] 0e b7 [2] 10 aa [2] 12 ab [2] 09 ad [2] 15 aa [2] 09 85 }

  condition:
    any of them
}