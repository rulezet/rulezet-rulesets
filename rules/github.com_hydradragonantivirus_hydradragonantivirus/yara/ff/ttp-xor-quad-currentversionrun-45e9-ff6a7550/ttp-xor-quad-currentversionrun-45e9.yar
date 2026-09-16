rule TTP_XOR_QUAD_CurrentVersionRun_45e9 {
  strings:
    $key_45e9 = { 16 86 [2] 32 88 [2] 19 a4 [2] 37 86 [2] 23 9d [2] 2c 87 [2] 32 9a [2] 30 9b [2] 2b 9d [2] 37 9a [2] 2b b5 }

  condition:
    any of them
}