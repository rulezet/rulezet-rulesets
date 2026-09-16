rule TTP_XOR_QUAD_CurrentVersionRun_33d8 {
  strings:
    $key_33d8 = { 60 b7 [2] 44 b9 [2] 6f 95 [2] 41 b7 [2] 55 ac [2] 5a b6 [2] 44 ab [2] 46 aa [2] 5d ac [2] 41 ab [2] 5d 84 }

  condition:
    any of them
}