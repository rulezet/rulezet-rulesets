rule TTP_XOR_QUAD_CurrentVersionRun_6369 {
  strings:
    $key_6369 = { 30 06 [2] 14 08 [2] 3f 24 [2] 11 06 [2] 05 1d [2] 0a 07 [2] 14 1a [2] 16 1b [2] 0d 1d [2] 11 1a [2] 0d 35 }

  condition:
    any of them
}