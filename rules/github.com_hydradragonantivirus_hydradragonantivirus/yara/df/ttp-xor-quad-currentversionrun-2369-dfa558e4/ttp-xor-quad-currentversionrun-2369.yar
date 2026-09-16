rule TTP_XOR_QUAD_CurrentVersionRun_2369 {
  strings:
    $key_2369 = { 70 06 [2] 54 08 [2] 7f 24 [2] 51 06 [2] 45 1d [2] 4a 07 [2] 54 1a [2] 56 1b [2] 4d 1d [2] 51 1a [2] 4d 35 }

  condition:
    any of them
}