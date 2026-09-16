rule TTP_XOR_QUAD_CurrentVersionRun_5909 {
  strings:
    $key_5909 = { 0a 66 [2] 2e 68 [2] 05 44 [2] 2b 66 [2] 3f 7d [2] 30 67 [2] 2e 7a [2] 2c 7b [2] 37 7d [2] 2b 7a [2] 37 55 }

  condition:
    any of them
}