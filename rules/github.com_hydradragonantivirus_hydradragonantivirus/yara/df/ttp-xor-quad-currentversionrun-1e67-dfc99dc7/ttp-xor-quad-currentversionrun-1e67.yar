rule TTP_XOR_QUAD_CurrentVersionRun_1e67 {
  strings:
    $key_1e67 = { 4d 08 [2] 69 06 [2] 42 2a [2] 6c 08 [2] 78 13 [2] 77 09 [2] 69 14 [2] 6b 15 [2] 70 13 [2] 6c 14 [2] 70 3b }

  condition:
    any of them
}