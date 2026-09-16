rule TTP_XOR_QUAD_CurrentVersionRun_4519 {
  strings:
    $key_4519 = { 16 76 [2] 32 78 [2] 19 54 [2] 37 76 [2] 23 6d [2] 2c 77 [2] 32 6a [2] 30 6b [2] 2b 6d [2] 37 6a [2] 2b 45 }

  condition:
    any of them
}