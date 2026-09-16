rule TTP_XOR_QUAD_CurrentVersionRun_6275 {
  strings:
    $key_6275 = { 31 1a [2] 15 14 [2] 3e 38 [2] 10 1a [2] 04 01 [2] 0b 1b [2] 15 06 [2] 17 07 [2] 0c 01 [2] 10 06 [2] 0c 29 }

  condition:
    any of them
}