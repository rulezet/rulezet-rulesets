rule TTP_XOR_QUAD_CurrentVersionRun_0b54 {
  strings:
    $key_0b54 = { 58 3b [2] 7c 35 [2] 57 19 [2] 79 3b [2] 6d 20 [2] 62 3a [2] 7c 27 [2] 7e 26 [2] 65 20 [2] 79 27 [2] 65 08 }

  condition:
    any of them
}