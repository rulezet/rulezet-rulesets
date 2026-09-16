rule TTP_XOR_QUAD_CurrentVersionRun_0b79 {
  strings:
    $key_0b79 = { 58 16 [2] 7c 18 [2] 57 34 [2] 79 16 [2] 6d 0d [2] 62 17 [2] 7c 0a [2] 7e 0b [2] 65 0d [2] 79 0a [2] 65 25 }

  condition:
    any of them
}