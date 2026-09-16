rule TTP_XOR_QUAD_CurrentVersionRun_7de8 {
  strings:
    $key_7de8 = { 2e 87 [2] 0a 89 [2] 21 a5 [2] 0f 87 [2] 1b 9c [2] 14 86 [2] 0a 9b [2] 08 9a [2] 13 9c [2] 0f 9b [2] 13 b4 }

  condition:
    any of them
}