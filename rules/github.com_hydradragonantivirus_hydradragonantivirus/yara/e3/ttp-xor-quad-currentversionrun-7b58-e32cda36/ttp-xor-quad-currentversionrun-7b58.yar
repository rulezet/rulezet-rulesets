rule TTP_XOR_QUAD_CurrentVersionRun_7b58 {
  strings:
    $key_7b58 = { 28 37 [2] 0c 39 [2] 27 15 [2] 09 37 [2] 1d 2c [2] 12 36 [2] 0c 2b [2] 0e 2a [2] 15 2c [2] 09 2b [2] 15 04 }

  condition:
    any of them
}