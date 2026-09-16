rule TTP_XOR_QUAD_CurrentVersionRun_4b69 {
  strings:
    $key_4b69 = { 18 06 [2] 3c 08 [2] 17 24 [2] 39 06 [2] 2d 1d [2] 22 07 [2] 3c 1a [2] 3e 1b [2] 25 1d [2] 39 1a [2] 25 35 }

  condition:
    any of them
}