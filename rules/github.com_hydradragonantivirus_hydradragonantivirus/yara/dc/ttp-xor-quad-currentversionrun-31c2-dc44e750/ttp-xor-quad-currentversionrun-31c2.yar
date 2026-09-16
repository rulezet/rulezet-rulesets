rule TTP_XOR_QUAD_CurrentVersionRun_31c2 {
  strings:
    $key_31c2 = { 62 ad [2] 46 a3 [2] 6d 8f [2] 43 ad [2] 57 b6 [2] 58 ac [2] 46 b1 [2] 44 b0 [2] 5f b6 [2] 43 b1 [2] 5f 9e }

  condition:
    any of them
}