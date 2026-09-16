rule TTP_XOR_QUAD_CurrentVersionRun_1e58 {
  strings:
    $key_1e58 = { 4d 37 [2] 69 39 [2] 42 15 [2] 6c 37 [2] 78 2c [2] 77 36 [2] 69 2b [2] 6b 2a [2] 70 2c [2] 6c 2b [2] 70 04 }

  condition:
    any of them
}