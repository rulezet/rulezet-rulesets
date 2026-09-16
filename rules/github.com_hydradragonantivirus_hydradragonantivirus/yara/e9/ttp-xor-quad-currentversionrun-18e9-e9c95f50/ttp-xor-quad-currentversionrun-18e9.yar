rule TTP_XOR_QUAD_CurrentVersionRun_18e9 {
  strings:
    $key_18e9 = { 4b 86 [2] 6f 88 [2] 44 a4 [2] 6a 86 [2] 7e 9d [2] 71 87 [2] 6f 9a [2] 6d 9b [2] 76 9d [2] 6a 9a [2] 76 b5 }

  condition:
    any of them
}