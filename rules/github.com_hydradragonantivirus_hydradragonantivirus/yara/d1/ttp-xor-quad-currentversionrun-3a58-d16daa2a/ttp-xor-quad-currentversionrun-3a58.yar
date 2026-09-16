rule TTP_XOR_QUAD_CurrentVersionRun_3a58 {
  strings:
    $key_3a58 = { 69 37 [2] 4d 39 [2] 66 15 [2] 48 37 [2] 5c 2c [2] 53 36 [2] 4d 2b [2] 4f 2a [2] 54 2c [2] 48 2b [2] 54 04 }

  condition:
    any of them
}