rule TTP_XOR_QUAD_CurrentVersionRun_7f4b {
  strings:
    $key_7f4b = { 2c 24 [2] 08 2a [2] 23 06 [2] 0d 24 [2] 19 3f [2] 16 25 [2] 08 38 [2] 0a 39 [2] 11 3f [2] 0d 38 [2] 11 17 }

  condition:
    any of them
}