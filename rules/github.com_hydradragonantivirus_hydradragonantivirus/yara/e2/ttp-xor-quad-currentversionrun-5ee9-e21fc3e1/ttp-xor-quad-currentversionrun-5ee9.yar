rule TTP_XOR_QUAD_CurrentVersionRun_5ee9 {
  strings:
    $key_5ee9 = { 0d 86 [2] 29 88 [2] 02 a4 [2] 2c 86 [2] 38 9d [2] 37 87 [2] 29 9a [2] 2b 9b [2] 30 9d [2] 2c 9a [2] 30 b5 }

  condition:
    any of them
}