rule TTP_XOR_QUAD_CurrentVersionRun_4504 {
  strings:
    $key_4504 = { 16 6b [2] 32 65 [2] 19 49 [2] 37 6b [2] 23 70 [2] 2c 6a [2] 32 77 [2] 30 76 [2] 2b 70 [2] 37 77 [2] 2b 58 }

  condition:
    any of them
}