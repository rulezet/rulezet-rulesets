rule TTP_XOR_QUAD_CurrentVersionRun_14c5 {
  strings:
    $key_14c5 = { 47 aa [2] 63 a4 [2] 48 88 [2] 66 aa [2] 72 b1 [2] 7d ab [2] 63 b6 [2] 61 b7 [2] 7a b1 [2] 66 b6 [2] 7a 99 }

  condition:
    any of them
}