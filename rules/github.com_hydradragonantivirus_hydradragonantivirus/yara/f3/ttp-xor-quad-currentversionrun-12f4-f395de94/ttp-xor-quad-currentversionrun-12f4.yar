rule TTP_XOR_QUAD_CurrentVersionRun_12f4 {
  strings:
    $key_12f4 = { 41 9b [2] 65 95 [2] 4e b9 [2] 60 9b [2] 74 80 [2] 7b 9a [2] 65 87 [2] 67 86 [2] 7c 80 [2] 60 87 [2] 7c a8 }

  condition:
    any of them
}