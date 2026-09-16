rule TTP_XOR_QUAD_CurrentVersionRun_65e4 {
  strings:
    $key_65e4 = { 36 8b [2] 12 85 [2] 39 a9 [2] 17 8b [2] 03 90 [2] 0c 8a [2] 12 97 [2] 10 96 [2] 0b 90 [2] 17 97 [2] 0b b8 }

  condition:
    any of them
}