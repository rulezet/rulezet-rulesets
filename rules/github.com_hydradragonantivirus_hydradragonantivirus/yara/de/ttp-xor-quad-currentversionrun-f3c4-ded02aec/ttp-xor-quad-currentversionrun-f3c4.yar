rule TTP_XOR_QUAD_CurrentVersionRun_f3c4 {
  strings:
    $key_f3c4 = { a0 ab [2] 84 a5 [2] af 89 [2] 81 ab [2] 95 b0 [2] 9a aa [2] 84 b7 [2] 86 b6 [2] 9d b0 [2] 81 b7 [2] 9d 98 }

  condition:
    any of them
}