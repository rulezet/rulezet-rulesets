rule TTP_XOR_QUAD_CurrentVersionRun_efd8 {
  strings:
    $key_efd8 = { bc b7 [2] 98 b9 [2] b3 95 [2] 9d b7 [2] 89 ac [2] 86 b6 [2] 98 ab [2] 9a aa [2] 81 ac [2] 9d ab [2] 81 84 }

  condition:
    any of them
}