rule TTP_XOR_QUAD_CurrentVersionRun_5d79 {
  strings:
    $key_5d79 = { 0e 16 [2] 2a 18 [2] 01 34 [2] 2f 16 [2] 3b 0d [2] 34 17 [2] 2a 0a [2] 28 0b [2] 33 0d [2] 2f 0a [2] 33 25 }

  condition:
    any of them
}