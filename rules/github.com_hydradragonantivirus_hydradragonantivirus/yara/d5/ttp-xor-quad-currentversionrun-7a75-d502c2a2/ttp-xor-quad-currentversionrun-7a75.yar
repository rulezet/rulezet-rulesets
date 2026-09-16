rule TTP_XOR_QUAD_CurrentVersionRun_7a75 {
  strings:
    $key_7a75 = { 29 1a [2] 0d 14 [2] 26 38 [2] 08 1a [2] 1c 01 [2] 13 1b [2] 0d 06 [2] 0f 07 [2] 14 01 [2] 08 06 [2] 14 29 }

  condition:
    any of them
}