rule TTP_XOR_QUAD_CurrentVersionRun_e7c5 {
  strings:
    $key_e7c5 = { b4 aa [2] 90 a4 [2] bb 88 [2] 95 aa [2] 81 b1 [2] 8e ab [2] 90 b6 [2] 92 b7 [2] 89 b1 [2] 95 b6 [2] 89 99 }

  condition:
    any of them
}