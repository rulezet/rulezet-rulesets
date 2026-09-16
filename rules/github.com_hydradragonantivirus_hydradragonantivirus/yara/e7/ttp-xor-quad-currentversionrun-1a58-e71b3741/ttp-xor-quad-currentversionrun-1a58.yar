rule TTP_XOR_QUAD_CurrentVersionRun_1a58 {
  strings:
    $key_1a58 = { 49 37 [2] 6d 39 [2] 46 15 [2] 68 37 [2] 7c 2c [2] 73 36 [2] 6d 2b [2] 6f 2a [2] 74 2c [2] 68 2b [2] 74 04 }

  condition:
    any of them
}