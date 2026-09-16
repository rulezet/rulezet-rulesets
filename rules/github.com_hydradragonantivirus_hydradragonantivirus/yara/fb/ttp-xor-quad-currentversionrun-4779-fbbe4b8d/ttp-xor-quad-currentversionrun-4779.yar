rule TTP_XOR_QUAD_CurrentVersionRun_4779 {
  strings:
    $key_4779 = { 14 16 [2] 30 18 [2] 1b 34 [2] 35 16 [2] 21 0d [2] 2e 17 [2] 30 0a [2] 32 0b [2] 29 0d [2] 35 0a [2] 29 25 }

  condition:
    any of them
}