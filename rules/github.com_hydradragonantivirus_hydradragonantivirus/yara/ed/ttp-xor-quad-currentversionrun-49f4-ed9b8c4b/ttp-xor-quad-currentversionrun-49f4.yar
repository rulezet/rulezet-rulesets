rule TTP_XOR_QUAD_CurrentVersionRun_49f4 {
  strings:
    $key_49f4 = { 1a 9b [2] 3e 95 [2] 15 b9 [2] 3b 9b [2] 2f 80 [2] 20 9a [2] 3e 87 [2] 3c 86 [2] 27 80 [2] 3b 87 [2] 27 a8 }

  condition:
    any of them
}