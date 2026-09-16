rule TTP_XOR_QUAD_CurrentVersionRun_60c4 {
  strings:
    $key_60c4 = { 33 ab [2] 17 a5 [2] 3c 89 [2] 12 ab [2] 06 b0 [2] 09 aa [2] 17 b7 [2] 15 b6 [2] 0e b0 [2] 12 b7 [2] 0e 98 }

  condition:
    any of them
}