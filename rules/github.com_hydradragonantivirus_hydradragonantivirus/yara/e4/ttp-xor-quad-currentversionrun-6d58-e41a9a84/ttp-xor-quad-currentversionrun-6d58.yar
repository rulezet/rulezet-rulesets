rule TTP_XOR_QUAD_CurrentVersionRun_6d58 {
  strings:
    $key_6d58 = { 3e 37 [2] 1a 39 [2] 31 15 [2] 1f 37 [2] 0b 2c [2] 04 36 [2] 1a 2b [2] 18 2a [2] 03 2c [2] 1f 2b [2] 03 04 }

  condition:
    any of them
}