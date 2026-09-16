rule TTP_XOR_QUAD_CurrentVersionRun_6525 {
  strings:
    $key_6525 = { 36 4a [2] 12 44 [2] 39 68 [2] 17 4a [2] 03 51 [2] 0c 4b [2] 12 56 [2] 10 57 [2] 0b 51 [2] 17 56 [2] 0b 79 }

  condition:
    any of them
}