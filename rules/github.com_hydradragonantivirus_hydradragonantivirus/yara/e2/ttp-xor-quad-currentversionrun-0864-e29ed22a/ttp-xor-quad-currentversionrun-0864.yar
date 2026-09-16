rule TTP_XOR_QUAD_CurrentVersionRun_0864 {
  strings:
    $key_0864 = { 5b 0b [2] 7f 05 [2] 54 29 [2] 7a 0b [2] 6e 10 [2] 61 0a [2] 7f 17 [2] 7d 16 [2] 66 10 [2] 7a 17 [2] 66 38 }

  condition:
    any of them
}