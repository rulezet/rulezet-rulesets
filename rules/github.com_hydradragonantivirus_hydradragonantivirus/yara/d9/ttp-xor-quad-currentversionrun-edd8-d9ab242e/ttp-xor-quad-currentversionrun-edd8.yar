rule TTP_XOR_QUAD_CurrentVersionRun_edd8 {
  strings:
    $key_edd8 = { be b7 [2] 9a b9 [2] b1 95 [2] 9f b7 [2] 8b ac [2] 84 b6 [2] 9a ab [2] 98 aa [2] 83 ac [2] 9f ab [2] 83 84 }

  condition:
    any of them
}