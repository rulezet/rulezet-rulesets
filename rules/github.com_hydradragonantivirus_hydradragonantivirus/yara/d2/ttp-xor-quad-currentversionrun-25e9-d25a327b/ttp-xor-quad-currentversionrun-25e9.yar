rule TTP_XOR_QUAD_CurrentVersionRun_25e9 {
  strings:
    $key_25e9 = { 76 86 [2] 52 88 [2] 79 a4 [2] 57 86 [2] 43 9d [2] 4c 87 [2] 52 9a [2] 50 9b [2] 4b 9d [2] 57 9a [2] 4b b5 }

  condition:
    any of them
}