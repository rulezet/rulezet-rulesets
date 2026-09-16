rule TTP_XOR_QUAD_CurrentVersionRun_4535 {
  strings:
    $key_4535 = { 16 5a [2] 32 54 [2] 19 78 [2] 37 5a [2] 23 41 [2] 2c 5b [2] 32 46 [2] 30 47 [2] 2b 41 [2] 37 46 [2] 2b 69 }

  condition:
    any of them
}