rule TTP_XOR_QUAD_CurrentVersionRun_5834 {
  strings:
    $key_5834 = { 0b 5b [2] 2f 55 [2] 04 79 [2] 2a 5b [2] 3e 40 [2] 31 5a [2] 2f 47 [2] 2d 46 [2] 36 40 [2] 2a 47 [2] 36 68 }

  condition:
    any of them
}