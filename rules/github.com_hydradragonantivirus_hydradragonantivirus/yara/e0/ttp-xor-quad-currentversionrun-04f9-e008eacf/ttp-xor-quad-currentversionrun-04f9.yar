rule TTP_XOR_QUAD_CurrentVersionRun_04f9 {
  strings:
    $key_04f9 = { 57 96 [2] 73 98 [2] 58 b4 [2] 76 96 [2] 62 8d [2] 6d 97 [2] 73 8a [2] 71 8b [2] 6a 8d [2] 76 8a [2] 6a a5 }

  condition:
    any of them
}