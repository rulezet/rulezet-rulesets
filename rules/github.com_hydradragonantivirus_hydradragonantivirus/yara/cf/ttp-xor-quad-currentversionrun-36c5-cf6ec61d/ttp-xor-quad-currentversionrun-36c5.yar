rule TTP_XOR_QUAD_CurrentVersionRun_36c5 {
  strings:
    $key_36c5 = { 65 aa [2] 41 a4 [2] 6a 88 [2] 44 aa [2] 50 b1 [2] 5f ab [2] 41 b6 [2] 43 b7 [2] 58 b1 [2] 44 b6 [2] 58 99 }

  condition:
    any of them
}