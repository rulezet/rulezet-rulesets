rule TTP_XOR_QUAD_CurrentVersionRun_5918 {
  strings:
    $key_5918 = { 0a 77 [2] 2e 79 [2] 05 55 [2] 2b 77 [2] 3f 6c [2] 30 76 [2] 2e 6b [2] 2c 6a [2] 37 6c [2] 2b 6b [2] 37 44 }

  condition:
    any of them
}