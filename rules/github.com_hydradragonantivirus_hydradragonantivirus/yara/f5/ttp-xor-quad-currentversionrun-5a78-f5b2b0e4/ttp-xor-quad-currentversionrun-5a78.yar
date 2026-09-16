rule TTP_XOR_QUAD_CurrentVersionRun_5a78 {
  strings:
    $key_5a78 = { 09 17 [2] 2d 19 [2] 06 35 [2] 28 17 [2] 3c 0c [2] 33 16 [2] 2d 0b [2] 2f 0a [2] 34 0c [2] 28 0b [2] 34 24 }

  condition:
    any of them
}