rule TTP_XOR_QUAD_CurrentVersionRun_7f59 {
  strings:
    $key_7f59 = { 2c 36 [2] 08 38 [2] 23 14 [2] 0d 36 [2] 19 2d [2] 16 37 [2] 08 2a [2] 0a 2b [2] 11 2d [2] 0d 2a [2] 11 05 }

  condition:
    any of them
}