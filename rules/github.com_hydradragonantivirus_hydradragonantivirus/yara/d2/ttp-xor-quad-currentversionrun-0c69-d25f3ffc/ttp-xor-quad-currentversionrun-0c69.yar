rule TTP_XOR_QUAD_CurrentVersionRun_0c69 {
  strings:
    $key_0c69 = { 5f 06 [2] 7b 08 [2] 50 24 [2] 7e 06 [2] 6a 1d [2] 65 07 [2] 7b 1a [2] 79 1b [2] 62 1d [2] 7e 1a [2] 62 35 }

  condition:
    any of them
}