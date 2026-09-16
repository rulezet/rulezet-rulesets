rule TTP_XOR_QUAD_CurrentVersionRun_27d9 {
  strings:
    $key_27d9 = { 74 b6 [2] 50 b8 [2] 7b 94 [2] 55 b6 [2] 41 ad [2] 4e b7 [2] 50 aa [2] 52 ab [2] 49 ad [2] 55 aa [2] 49 85 }

  condition:
    any of them
}