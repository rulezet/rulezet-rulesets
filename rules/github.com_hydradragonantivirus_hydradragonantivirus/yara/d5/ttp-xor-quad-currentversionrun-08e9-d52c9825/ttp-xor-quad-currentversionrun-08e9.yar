rule TTP_XOR_QUAD_CurrentVersionRun_08e9 {
  strings:
    $key_08e9 = { 5b 86 [2] 7f 88 [2] 54 a4 [2] 7a 86 [2] 6e 9d [2] 61 87 [2] 7f 9a [2] 7d 9b [2] 66 9d [2] 7a 9a [2] 66 b5 }

  condition:
    any of them
}