rule TTP_XOR_QUAD_CurrentVersionRun_22f4 {
  strings:
    $key_22f4 = { 71 9b [2] 55 95 [2] 7e b9 [2] 50 9b [2] 44 80 [2] 4b 9a [2] 55 87 [2] 57 86 [2] 4c 80 [2] 50 87 [2] 4c a8 }

  condition:
    any of them
}