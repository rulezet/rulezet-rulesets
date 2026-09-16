rule TTP_XOR_QUAD_CurrentVersionRun_4545 {
  strings:
    $key_4545 = { 16 2a [2] 32 24 [2] 19 08 [2] 37 2a [2] 23 31 [2] 2c 2b [2] 32 36 [2] 30 37 [2] 2b 31 [2] 37 36 [2] 2b 19 }

  condition:
    any of them
}