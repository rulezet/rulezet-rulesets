rule TTP_XOR_QUAD_CurrentVersionRun_f667 {
  strings:
    $key_f667 = { a5 08 [2] 81 06 [2] aa 2a [2] 84 08 [2] 90 13 [2] 9f 09 [2] 81 14 [2] 83 15 [2] 98 13 [2] 84 14 [2] 98 3b }

  condition:
    any of them
}