rule TTP_XOR_QUAD_CurrentVersionRun_60c5 {
  strings:
    $key_60c5 = { 33 aa [2] 17 a4 [2] 3c 88 [2] 12 aa [2] 06 b1 [2] 09 ab [2] 17 b6 [2] 15 b7 [2] 0e b1 [2] 12 b6 [2] 0e 99 }

  condition:
    any of them
}