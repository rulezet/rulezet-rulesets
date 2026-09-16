rule TTP_XOR_QUAD_CurrentVersionRun_75c5 {
  strings:
    $key_75c5 = { 26 aa [2] 02 a4 [2] 29 88 [2] 07 aa [2] 13 b1 [2] 1c ab [2] 02 b6 [2] 00 b7 [2] 1b b1 [2] 07 b6 [2] 1b 99 }

  condition:
    any of them
}