rule TTP_XOR_QUAD_CurrentVersionRun_7f19 {
  strings:
    $key_7f19 = { 2c 76 [2] 08 78 [2] 23 54 [2] 0d 76 [2] 19 6d [2] 16 77 [2] 08 6a [2] 0a 6b [2] 11 6d [2] 0d 6a [2] 11 45 }

  condition:
    any of them
}