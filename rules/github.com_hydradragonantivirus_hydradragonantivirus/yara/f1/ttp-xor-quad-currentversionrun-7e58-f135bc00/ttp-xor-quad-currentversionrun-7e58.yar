rule TTP_XOR_QUAD_CurrentVersionRun_7e58 {
  strings:
    $key_7e58 = { 2d 37 [2] 09 39 [2] 22 15 [2] 0c 37 [2] 18 2c [2] 17 36 [2] 09 2b [2] 0b 2a [2] 10 2c [2] 0c 2b [2] 10 04 }

  condition:
    any of them
}