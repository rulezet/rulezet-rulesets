rule TTP_XOR_QUAD_CurrentVersionRun_10e8 {
  strings:
    $key_10e8 = { 43 87 [2] 67 89 [2] 4c a5 [2] 62 87 [2] 76 9c [2] 79 86 [2] 67 9b [2] 65 9a [2] 7e 9c [2] 62 9b [2] 7e b4 }

  condition:
    any of them
}