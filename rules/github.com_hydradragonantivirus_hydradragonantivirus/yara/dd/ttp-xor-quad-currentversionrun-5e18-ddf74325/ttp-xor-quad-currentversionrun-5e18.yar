rule TTP_XOR_QUAD_CurrentVersionRun_5e18 {
  strings:
    $key_5e18 = { 0d 77 [2] 29 79 [2] 02 55 [2] 2c 77 [2] 38 6c [2] 37 76 [2] 29 6b [2] 2b 6a [2] 30 6c [2] 2c 6b [2] 30 44 }

  condition:
    any of them
}