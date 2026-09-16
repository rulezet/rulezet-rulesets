rule TTP_XOR_QUAD_CurrentVersionRun_2fe9 {
  strings:
    $key_2fe9 = { 7c 86 [2] 58 88 [2] 73 a4 [2] 5d 86 [2] 49 9d [2] 46 87 [2] 58 9a [2] 5a 9b [2] 41 9d [2] 5d 9a [2] 41 b5 }

  condition:
    any of them
}