rule TTP_XOR_QUAD_CurrentVersionRun_40c5 {
  strings:
    $key_40c5 = { 13 aa [2] 37 a4 [2] 1c 88 [2] 32 aa [2] 26 b1 [2] 29 ab [2] 37 b6 [2] 35 b7 [2] 2e b1 [2] 32 b6 [2] 2e 99 }

  condition:
    any of them
}