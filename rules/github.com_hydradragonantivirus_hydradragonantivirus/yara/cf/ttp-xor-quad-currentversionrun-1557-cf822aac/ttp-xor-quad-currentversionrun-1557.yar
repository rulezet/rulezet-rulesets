rule TTP_XOR_QUAD_CurrentVersionRun_1557 {
  strings:
    $key_1557 = { 46 38 [2] 62 36 [2] 49 1a [2] 67 38 [2] 73 23 [2] 7c 39 [2] 62 24 [2] 60 25 [2] 7b 23 [2] 67 24 [2] 7b 0b }

  condition:
    any of them
}