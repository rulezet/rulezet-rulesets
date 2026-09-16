rule TTP_XOR_QUAD_CurrentVersionRun_6548 {
  strings:
    $key_6548 = { 36 27 [2] 12 29 [2] 39 05 [2] 17 27 [2] 03 3c [2] 0c 26 [2] 12 3b [2] 10 3a [2] 0b 3c [2] 17 3b [2] 0b 14 }

  condition:
    any of them
}