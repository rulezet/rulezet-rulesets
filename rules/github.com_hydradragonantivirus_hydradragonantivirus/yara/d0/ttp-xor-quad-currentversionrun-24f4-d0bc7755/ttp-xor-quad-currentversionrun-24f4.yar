rule TTP_XOR_QUAD_CurrentVersionRun_24f4 {
  strings:
    $key_24f4 = { 77 9b [2] 53 95 [2] 78 b9 [2] 56 9b [2] 42 80 [2] 4d 9a [2] 53 87 [2] 51 86 [2] 4a 80 [2] 56 87 [2] 4a a8 }

  condition:
    any of them
}