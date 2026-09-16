rule TTP_XOR_QUAD_CurrentVersionRun_6559 {
  strings:
    $key_6559 = { 36 36 [2] 12 38 [2] 39 14 [2] 17 36 [2] 03 2d [2] 0c 37 [2] 12 2a [2] 10 2b [2] 0b 2d [2] 17 2a [2] 0b 05 }

  condition:
    any of them
}