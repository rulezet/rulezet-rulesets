rule TTP_XOR_QUAD_CurrentVersionRun_1269 {
  strings:
    $key_1269 = { 41 06 [2] 65 08 [2] 4e 24 [2] 60 06 [2] 74 1d [2] 7b 07 [2] 65 1a [2] 67 1b [2] 7c 1d [2] 60 1a [2] 7c 35 }

  condition:
    any of them
}