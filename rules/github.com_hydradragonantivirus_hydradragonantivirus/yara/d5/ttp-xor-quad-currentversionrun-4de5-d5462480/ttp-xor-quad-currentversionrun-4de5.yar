rule TTP_XOR_QUAD_CurrentVersionRun_4de5 {
  strings:
    $key_4de5 = { 1e 8a [2] 3a 84 [2] 11 a8 [2] 3f 8a [2] 2b 91 [2] 24 8b [2] 3a 96 [2] 38 97 [2] 23 91 [2] 3f 96 [2] 23 b9 }

  condition:
    any of them
}