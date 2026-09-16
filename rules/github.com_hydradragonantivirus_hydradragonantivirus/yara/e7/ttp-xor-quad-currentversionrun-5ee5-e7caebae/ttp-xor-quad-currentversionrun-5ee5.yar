rule TTP_XOR_QUAD_CurrentVersionRun_5ee5 {
  strings:
    $key_5ee5 = { 0d 8a [2] 29 84 [2] 02 a8 [2] 2c 8a [2] 38 91 [2] 37 8b [2] 29 96 [2] 2b 97 [2] 30 91 [2] 2c 96 [2] 30 b9 }

  condition:
    any of them
}