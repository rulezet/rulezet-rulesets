rule TTP_XOR_QUAD_CurrentVersionRun_0969 {
  strings:
    $key_0969 = { 5a 06 [2] 7e 08 [2] 55 24 [2] 7b 06 [2] 6f 1d [2] 60 07 [2] 7e 1a [2] 7c 1b [2] 67 1d [2] 7b 1a [2] 67 35 }

  condition:
    any of them
}