rule TTP_XOR_QUAD_CurrentVersionRun_2558 {
  strings:
    $key_2558 = { 76 37 [2] 52 39 [2] 79 15 [2] 57 37 [2] 43 2c [2] 4c 36 [2] 52 2b [2] 50 2a [2] 4b 2c [2] 57 2b [2] 4b 04 }

  condition:
    any of them
}