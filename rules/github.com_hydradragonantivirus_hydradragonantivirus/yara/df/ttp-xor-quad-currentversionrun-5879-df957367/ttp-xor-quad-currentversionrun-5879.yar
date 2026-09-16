rule TTP_XOR_QUAD_CurrentVersionRun_5879 {
  strings:
    $key_5879 = { 0b 16 [2] 2f 18 [2] 04 34 [2] 2a 16 [2] 3e 0d [2] 31 17 [2] 2f 0a [2] 2d 0b [2] 36 0d [2] 2a 0a [2] 36 25 }

  condition:
    any of them
}