rule TTP_XOR_QUAD_CurrentVersionRun_6455 {
  strings:
    $key_6455 = { 37 3a [2] 13 34 [2] 38 18 [2] 16 3a [2] 02 21 [2] 0d 3b [2] 13 26 [2] 11 27 [2] 0a 21 [2] 16 26 [2] 0a 09 }

  condition:
    any of them
}