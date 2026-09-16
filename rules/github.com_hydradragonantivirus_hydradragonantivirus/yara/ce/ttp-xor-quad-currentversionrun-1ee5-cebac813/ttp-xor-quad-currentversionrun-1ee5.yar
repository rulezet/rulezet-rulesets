rule TTP_XOR_QUAD_CurrentVersionRun_1ee5 {
  strings:
    $key_1ee5 = { 4d 8a [2] 69 84 [2] 42 a8 [2] 6c 8a [2] 78 91 [2] 77 8b [2] 69 96 [2] 6b 97 [2] 70 91 [2] 6c 96 [2] 70 b9 }

  condition:
    any of them
}