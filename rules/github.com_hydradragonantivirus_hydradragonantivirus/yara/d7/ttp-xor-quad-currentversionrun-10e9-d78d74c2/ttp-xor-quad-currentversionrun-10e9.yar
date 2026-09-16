rule TTP_XOR_QUAD_CurrentVersionRun_10e9 {
  strings:
    $key_10e9 = { 43 86 [2] 67 88 [2] 4c a4 [2] 62 86 [2] 76 9d [2] 79 87 [2] 67 9a [2] 65 9b [2] 7e 9d [2] 62 9a [2] 7e b5 }

  condition:
    any of them
}