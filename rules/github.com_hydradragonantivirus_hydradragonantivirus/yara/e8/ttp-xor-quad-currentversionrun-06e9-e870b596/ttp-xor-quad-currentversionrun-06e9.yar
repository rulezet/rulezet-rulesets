rule TTP_XOR_QUAD_CurrentVersionRun_06e9 {
  strings:
    $key_06e9 = { 55 86 [2] 71 88 [2] 5a a4 [2] 74 86 [2] 60 9d [2] 6f 87 [2] 71 9a [2] 73 9b [2] 68 9d [2] 74 9a [2] 68 b5 }

  condition:
    any of them
}