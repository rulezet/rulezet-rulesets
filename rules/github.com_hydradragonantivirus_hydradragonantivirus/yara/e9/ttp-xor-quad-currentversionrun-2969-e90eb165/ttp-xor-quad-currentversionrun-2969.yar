rule TTP_XOR_QUAD_CurrentVersionRun_2969 {
  strings:
    $key_2969 = { 7a 06 [2] 5e 08 [2] 75 24 [2] 5b 06 [2] 4f 1d [2] 40 07 [2] 5e 1a [2] 5c 1b [2] 47 1d [2] 5b 1a [2] 47 35 }

  condition:
    any of them
}