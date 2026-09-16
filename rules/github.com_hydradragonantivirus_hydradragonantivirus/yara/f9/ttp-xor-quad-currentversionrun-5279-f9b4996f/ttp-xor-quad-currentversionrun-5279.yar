rule TTP_XOR_QUAD_CurrentVersionRun_5279 {
  strings:
    $key_5279 = { 01 16 [2] 25 18 [2] 0e 34 [2] 20 16 [2] 34 0d [2] 3b 17 [2] 25 0a [2] 27 0b [2] 3c 0d [2] 20 0a [2] 3c 25 }

  condition:
    any of them
}