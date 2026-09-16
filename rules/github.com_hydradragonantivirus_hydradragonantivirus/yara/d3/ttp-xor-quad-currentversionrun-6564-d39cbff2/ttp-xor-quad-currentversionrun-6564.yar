rule TTP_XOR_QUAD_CurrentVersionRun_6564 {
  strings:
    $key_6564 = { 36 0b [2] 12 05 [2] 39 29 [2] 17 0b [2] 03 10 [2] 0c 0a [2] 12 17 [2] 10 16 [2] 0b 10 [2] 17 17 [2] 0b 38 }

  condition:
    any of them
}