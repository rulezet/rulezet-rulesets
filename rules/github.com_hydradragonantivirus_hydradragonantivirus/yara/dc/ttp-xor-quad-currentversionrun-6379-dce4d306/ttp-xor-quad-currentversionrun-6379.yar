rule TTP_XOR_QUAD_CurrentVersionRun_6379 {
  strings:
    $key_6379 = { 30 16 [2] 14 18 [2] 3f 34 [2] 11 16 [2] 05 0d [2] 0a 17 [2] 14 0a [2] 16 0b [2] 0d 0d [2] 11 0a [2] 0d 25 }

  condition:
    any of them
}