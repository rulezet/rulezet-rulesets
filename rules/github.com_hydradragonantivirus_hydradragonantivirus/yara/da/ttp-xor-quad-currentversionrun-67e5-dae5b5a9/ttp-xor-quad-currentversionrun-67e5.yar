rule TTP_XOR_QUAD_CurrentVersionRun_67e5 {
  strings:
    $key_67e5 = { 34 8a [2] 10 84 [2] 3b a8 [2] 15 8a [2] 01 91 [2] 0e 8b [2] 10 96 [2] 12 97 [2] 09 91 [2] 15 96 [2] 09 b9 }

  condition:
    any of them
}