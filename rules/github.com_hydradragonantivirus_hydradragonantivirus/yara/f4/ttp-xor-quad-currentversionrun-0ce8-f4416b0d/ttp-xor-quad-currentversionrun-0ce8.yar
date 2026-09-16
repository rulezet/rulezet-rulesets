rule TTP_XOR_QUAD_CurrentVersionRun_0ce8 {
  strings:
    $key_0ce8 = { 5f 87 [2] 7b 89 [2] 50 a5 [2] 7e 87 [2] 6a 9c [2] 65 86 [2] 7b 9b [2] 79 9a [2] 62 9c [2] 7e 9b [2] 62 b4 }

  condition:
    any of them
}