rule TTP_XOR_QUAD_CurrentVersionRun_f637 {
  strings:
    $key_f637 = { a5 58 [2] 81 56 [2] aa 7a [2] 84 58 [2] 90 43 [2] 9f 59 [2] 81 44 [2] 83 45 [2] 98 43 [2] 84 44 [2] 98 6b }

  condition:
    any of them
}