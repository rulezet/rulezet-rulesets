rule TTP_XOR_QUAD_CurrentVersionRun_1775 {
  strings:
    $key_1775 = { 44 1a [2] 60 14 [2] 4b 38 [2] 65 1a [2] 71 01 [2] 7e 1b [2] 60 06 [2] 62 07 [2] 79 01 [2] 65 06 [2] 79 29 }

  condition:
    any of them
}