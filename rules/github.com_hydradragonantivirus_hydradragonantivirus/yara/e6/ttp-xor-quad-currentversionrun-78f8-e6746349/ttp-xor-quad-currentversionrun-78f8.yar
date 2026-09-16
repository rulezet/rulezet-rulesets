rule TTP_XOR_QUAD_CurrentVersionRun_78f8 {
  strings:
    $key_78f8 = { 2b 97 [2] 0f 99 [2] 24 b5 [2] 0a 97 [2] 1e 8c [2] 11 96 [2] 0f 8b [2] 0d 8a [2] 16 8c [2] 0a 8b [2] 16 a4 }

  condition:
    any of them
}