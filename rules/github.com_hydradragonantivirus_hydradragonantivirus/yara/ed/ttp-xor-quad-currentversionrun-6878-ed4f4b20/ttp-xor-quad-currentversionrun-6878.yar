rule TTP_XOR_QUAD_CurrentVersionRun_6878 {
  strings:
    $key_6878 = { 3b 17 [2] 1f 19 [2] 34 35 [2] 1a 17 [2] 0e 0c [2] 01 16 [2] 1f 0b [2] 1d 0a [2] 06 0c [2] 1a 0b [2] 06 24 }

  condition:
    any of them
}