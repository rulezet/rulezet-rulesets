rule TTP_XOR_QUAD_CurrentVersionRun_2675 {
  strings:
    $key_2675 = { 75 1a [2] 51 14 [2] 7a 38 [2] 54 1a [2] 40 01 [2] 4f 1b [2] 51 06 [2] 53 07 [2] 48 01 [2] 54 06 [2] 48 29 }

  condition:
    any of them
}