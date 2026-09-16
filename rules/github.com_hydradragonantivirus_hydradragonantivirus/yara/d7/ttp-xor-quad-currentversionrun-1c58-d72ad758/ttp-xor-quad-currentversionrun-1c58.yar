rule TTP_XOR_QUAD_CurrentVersionRun_1c58 {
  strings:
    $key_1c58 = { 4f 37 [2] 6b 39 [2] 40 15 [2] 6e 37 [2] 7a 2c [2] 75 36 [2] 6b 2b [2] 69 2a [2] 72 2c [2] 6e 2b [2] 72 04 }

  condition:
    any of them
}