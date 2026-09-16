rule TTP_XOR_QUAD_CurrentVersionRun_04f8 {
  strings:
    $key_04f8 = { 57 97 [2] 73 99 [2] 58 b5 [2] 76 97 [2] 62 8c [2] 6d 96 [2] 73 8b [2] 71 8a [2] 6a 8c [2] 76 8b [2] 6a a4 }

  condition:
    any of them
}