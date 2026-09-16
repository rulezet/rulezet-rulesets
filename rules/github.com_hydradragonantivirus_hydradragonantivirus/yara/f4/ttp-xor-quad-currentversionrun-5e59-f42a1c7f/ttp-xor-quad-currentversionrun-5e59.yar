rule TTP_XOR_QUAD_CurrentVersionRun_5e59 {
  strings:
    $key_5e59 = { 0d 36 [2] 29 38 [2] 02 14 [2] 2c 36 [2] 38 2d [2] 37 37 [2] 29 2a [2] 2b 2b [2] 30 2d [2] 2c 2a [2] 30 05 }

  condition:
    any of them
}