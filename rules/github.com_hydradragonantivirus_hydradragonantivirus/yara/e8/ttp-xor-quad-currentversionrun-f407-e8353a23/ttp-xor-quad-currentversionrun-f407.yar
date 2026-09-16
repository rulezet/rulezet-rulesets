rule TTP_XOR_QUAD_CurrentVersionRun_f407 {
  strings:
    $key_f407 = { a7 68 [2] 83 66 [2] a8 4a [2] 86 68 [2] 92 73 [2] 9d 69 [2] 83 74 [2] 81 75 [2] 9a 73 [2] 86 74 [2] 9a 5b }

  condition:
    any of them
}