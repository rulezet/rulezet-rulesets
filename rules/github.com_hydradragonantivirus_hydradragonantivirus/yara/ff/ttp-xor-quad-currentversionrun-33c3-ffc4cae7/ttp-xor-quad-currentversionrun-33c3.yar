rule TTP_XOR_QUAD_CurrentVersionRun_33c3 {
  strings:
    $key_33c3 = { 60 ac [2] 44 a2 [2] 6f 8e [2] 41 ac [2] 55 b7 [2] 5a ad [2] 44 b0 [2] 46 b1 [2] 5d b7 [2] 41 b0 [2] 5d 9f }

  condition:
    any of them
}