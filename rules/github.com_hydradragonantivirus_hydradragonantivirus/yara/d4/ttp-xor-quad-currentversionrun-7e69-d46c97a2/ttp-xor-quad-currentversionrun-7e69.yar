rule TTP_XOR_QUAD_CurrentVersionRun_7e69 {
  strings:
    $key_7e69 = { 2d 06 [2] 09 08 [2] 22 24 [2] 0c 06 [2] 18 1d [2] 17 07 [2] 09 1a [2] 0b 1b [2] 10 1d [2] 0c 1a [2] 10 35 }

  condition:
    any of them
}