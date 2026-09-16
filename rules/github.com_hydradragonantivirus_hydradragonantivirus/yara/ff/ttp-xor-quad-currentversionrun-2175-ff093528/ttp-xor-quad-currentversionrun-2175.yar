rule TTP_XOR_QUAD_CurrentVersionRun_2175 {
  strings:
    $key_2175 = { 72 1a [2] 56 14 [2] 7d 38 [2] 53 1a [2] 47 01 [2] 48 1b [2] 56 06 [2] 54 07 [2] 4f 01 [2] 53 06 [2] 4f 29 }

  condition:
    any of them
}