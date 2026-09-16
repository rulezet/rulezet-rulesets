rule TTP_XOR_QUAD_CurrentVersionRun_5579 {
  strings:
    $key_5579 = { 06 16 [2] 22 18 [2] 09 34 [2] 27 16 [2] 33 0d [2] 3c 17 [2] 22 0a [2] 20 0b [2] 3b 0d [2] 27 0a [2] 3b 25 }

  condition:
    any of them
}