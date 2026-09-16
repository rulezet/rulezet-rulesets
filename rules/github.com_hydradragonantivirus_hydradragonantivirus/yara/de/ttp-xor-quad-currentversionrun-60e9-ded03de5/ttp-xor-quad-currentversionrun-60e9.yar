rule TTP_XOR_QUAD_CurrentVersionRun_60e9 {
  strings:
    $key_60e9 = { 33 86 [2] 17 88 [2] 3c a4 [2] 12 86 [2] 06 9d [2] 09 87 [2] 17 9a [2] 15 9b [2] 0e 9d [2] 12 9a [2] 0e b5 }

  condition:
    any of them
}