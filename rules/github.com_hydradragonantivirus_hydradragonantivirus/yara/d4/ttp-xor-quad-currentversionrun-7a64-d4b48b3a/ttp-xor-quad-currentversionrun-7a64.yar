rule TTP_XOR_QUAD_CurrentVersionRun_7a64 {
  strings:
    $key_7a64 = { 29 0b [2] 0d 05 [2] 26 29 [2] 08 0b [2] 1c 10 [2] 13 0a [2] 0d 17 [2] 0f 16 [2] 14 10 [2] 08 17 [2] 14 38 }

  condition:
    any of them
}