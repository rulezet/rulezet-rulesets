rule TTP_XOR_QUAD_CurrentVersionRun_1d58 {
  strings:
    $key_1d58 = { 4e 37 [2] 6a 39 [2] 41 15 [2] 6f 37 [2] 7b 2c [2] 74 36 [2] 6a 2b [2] 68 2a [2] 73 2c [2] 6f 2b [2] 73 04 }

  condition:
    any of them
}