rule TTP_XOR_QUAD_CurrentVersionRun_1ae9 {
  strings:
    $key_1ae9 = { 49 86 [2] 6d 88 [2] 46 a4 [2] 68 86 [2] 7c 9d [2] 73 87 [2] 6d 9a [2] 6f 9b [2] 74 9d [2] 68 9a [2] 74 b5 }

  condition:
    any of them
}