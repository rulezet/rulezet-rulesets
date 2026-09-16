rule TTP_XOR_QUAD_CurrentVersionRun_6554 {
  strings:
    $key_6554 = { 36 3b [2] 12 35 [2] 39 19 [2] 17 3b [2] 03 20 [2] 0c 3a [2] 12 27 [2] 10 26 [2] 0b 20 [2] 17 27 [2] 0b 08 }

  condition:
    any of them
}