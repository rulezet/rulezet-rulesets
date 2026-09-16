rule TTP_XOR_QUAD_CurrentVersionRun_0b58 {
  strings:
    $key_0b58 = { 58 37 [2] 7c 39 [2] 57 15 [2] 79 37 [2] 6d 2c [2] 62 36 [2] 7c 2b [2] 7e 2a [2] 65 2c [2] 79 2b [2] 65 04 }

  condition:
    any of them
}