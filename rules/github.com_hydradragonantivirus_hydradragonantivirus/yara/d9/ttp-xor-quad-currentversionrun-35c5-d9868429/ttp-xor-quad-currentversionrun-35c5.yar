rule TTP_XOR_QUAD_CurrentVersionRun_35c5 {
  strings:
    $key_35c5 = { 66 aa [2] 42 a4 [2] 69 88 [2] 47 aa [2] 53 b1 [2] 5c ab [2] 42 b6 [2] 40 b7 [2] 5b b1 [2] 47 b6 [2] 5b 99 }

  condition:
    any of them
}