rule TTP_XOR_QUAD_CurrentVersionRun_2ae9 {
  strings:
    $key_2ae9 = { 79 86 [2] 5d 88 [2] 76 a4 [2] 58 86 [2] 4c 9d [2] 43 87 [2] 5d 9a [2] 5f 9b [2] 44 9d [2] 58 9a [2] 44 b5 }

  condition:
    any of them
}