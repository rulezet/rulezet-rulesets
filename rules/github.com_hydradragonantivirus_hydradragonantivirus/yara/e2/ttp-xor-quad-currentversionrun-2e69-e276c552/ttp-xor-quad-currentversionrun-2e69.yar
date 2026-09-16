rule TTP_XOR_QUAD_CurrentVersionRun_2e69 {
  strings:
    $key_2e69 = { 7d 06 [2] 59 08 [2] 72 24 [2] 5c 06 [2] 48 1d [2] 47 07 [2] 59 1a [2] 5b 1b [2] 40 1d [2] 5c 1a [2] 40 35 }

  condition:
    any of them
}