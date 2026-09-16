rule TTP_XOR_QUAD_CurrentVersionRun_1074 {
  strings:
    $key_1074 = { 43 1b [2] 67 15 [2] 4c 39 [2] 62 1b [2] 76 00 [2] 79 1a [2] 67 07 [2] 65 06 [2] 7e 00 [2] 62 07 [2] 7e 28 }

  condition:
    any of them
}