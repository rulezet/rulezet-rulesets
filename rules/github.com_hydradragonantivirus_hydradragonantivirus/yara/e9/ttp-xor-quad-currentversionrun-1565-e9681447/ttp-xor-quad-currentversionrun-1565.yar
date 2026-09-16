rule TTP_XOR_QUAD_CurrentVersionRun_1565 {
  strings:
    $key_1565 = { 46 0a [2] 62 04 [2] 49 28 [2] 67 0a [2] 73 11 [2] 7c 0b [2] 62 16 [2] 60 17 [2] 7b 11 [2] 67 16 [2] 7b 39 }

  condition:
    any of them
}