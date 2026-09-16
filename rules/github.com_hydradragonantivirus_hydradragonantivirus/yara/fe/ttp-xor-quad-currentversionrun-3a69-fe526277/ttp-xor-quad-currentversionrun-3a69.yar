rule TTP_XOR_QUAD_CurrentVersionRun_3a69 {
  strings:
    $key_3a69 = { 69 06 [2] 4d 08 [2] 66 24 [2] 48 06 [2] 5c 1d [2] 53 07 [2] 4d 1a [2] 4f 1b [2] 54 1d [2] 48 1a [2] 54 35 }

  condition:
    any of them
}