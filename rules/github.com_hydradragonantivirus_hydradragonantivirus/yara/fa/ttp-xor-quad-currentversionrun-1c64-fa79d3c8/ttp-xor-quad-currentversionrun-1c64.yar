rule TTP_XOR_QUAD_CurrentVersionRun_1c64 {
  strings:
    $key_1c64 = { 4f 0b [2] 6b 05 [2] 40 29 [2] 6e 0b [2] 7a 10 [2] 75 0a [2] 6b 17 [2] 69 16 [2] 72 10 [2] 6e 17 [2] 72 38 }

  condition:
    any of them
}