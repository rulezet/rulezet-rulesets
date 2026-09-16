rule TTP_XOR_QUAD_CurrentVersionRun_f8d8 {
  strings:
    $key_f8d8 = { ab b7 [2] 8f b9 [2] a4 95 [2] 8a b7 [2] 9e ac [2] 91 b6 [2] 8f ab [2] 8d aa [2] 96 ac [2] 8a ab [2] 96 84 }

  condition:
    any of them
}