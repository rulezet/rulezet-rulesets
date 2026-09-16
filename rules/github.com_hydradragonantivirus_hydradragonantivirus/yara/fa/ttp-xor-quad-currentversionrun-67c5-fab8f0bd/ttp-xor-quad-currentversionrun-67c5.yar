rule TTP_XOR_QUAD_CurrentVersionRun_67c5 {
  strings:
    $key_67c5 = { 34 aa [2] 10 a4 [2] 3b 88 [2] 15 aa [2] 01 b1 [2] 0e ab [2] 10 b6 [2] 12 b7 [2] 09 b1 [2] 15 b6 [2] 09 99 }

  condition:
    any of them
}