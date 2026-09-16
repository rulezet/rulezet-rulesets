rule TTP_XOR_QUAD_CurrentVersionRun_1c69 {
  strings:
    $key_1c69 = { 4f 06 [2] 6b 08 [2] 40 24 [2] 6e 06 [2] 7a 1d [2] 75 07 [2] 6b 1a [2] 69 1b [2] 72 1d [2] 6e 1a [2] 72 35 }

  condition:
    any of them
}