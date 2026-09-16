rule TTP_XOR_QUAD_CurrentVersionRun_46c5 {
  strings:
    $key_46c5 = { 15 aa [2] 31 a4 [2] 1a 88 [2] 34 aa [2] 20 b1 [2] 2f ab [2] 31 b6 [2] 33 b7 [2] 28 b1 [2] 34 b6 [2] 28 99 }

  condition:
    any of them
}