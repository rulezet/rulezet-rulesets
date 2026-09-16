rule TTP_XOR_QUAD_CurrentVersionRun_f4d9 {
  strings:
    $key_f4d9 = { a7 b6 [2] 83 b8 [2] a8 94 [2] 86 b6 [2] 92 ad [2] 9d b7 [2] 83 aa [2] 81 ab [2] 9a ad [2] 86 aa [2] 9a 85 }

  condition:
    any of them
}