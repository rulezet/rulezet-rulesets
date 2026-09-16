rule TTP_XOR_QUAD_CurrentVersionRun_0ce9 {
  strings:
    $key_0ce9 = { 5f 86 [2] 7b 88 [2] 50 a4 [2] 7e 86 [2] 6a 9d [2] 65 87 [2] 7b 9a [2] 79 9b [2] 62 9d [2] 7e 9a [2] 62 b5 }

  condition:
    any of them
}