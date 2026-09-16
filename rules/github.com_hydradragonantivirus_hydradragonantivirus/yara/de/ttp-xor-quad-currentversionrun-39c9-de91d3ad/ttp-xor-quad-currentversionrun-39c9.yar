rule TTP_XOR_QUAD_CurrentVersionRun_39c9 {
  strings:
    $key_39c9 = { 6a a6 [2] 4e a8 [2] 65 84 [2] 4b a6 [2] 5f bd [2] 50 a7 [2] 4e ba [2] 4c bb [2] 57 bd [2] 4b ba [2] 57 95 }

  condition:
    any of them
}