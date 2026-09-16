rule TTP_XOR_QUAD_CurrentVersionRun_02f5 {
  strings:
    $key_02f5 = { 51 9a [2] 75 94 [2] 5e b8 [2] 70 9a [2] 64 81 [2] 6b 9b [2] 75 86 [2] 77 87 [2] 6c 81 [2] 70 86 [2] 6c a9 }

  condition:
    any of them
}