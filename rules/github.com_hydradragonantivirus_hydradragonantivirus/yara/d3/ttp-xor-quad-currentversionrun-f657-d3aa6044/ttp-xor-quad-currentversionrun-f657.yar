rule TTP_XOR_QUAD_CurrentVersionRun_f657 {
  strings:
    $key_f657 = { a5 38 [2] 81 36 [2] aa 1a [2] 84 38 [2] 90 23 [2] 9f 39 [2] 81 24 [2] 83 25 [2] 98 23 [2] 84 24 [2] 98 0b }

  condition:
    any of them
}