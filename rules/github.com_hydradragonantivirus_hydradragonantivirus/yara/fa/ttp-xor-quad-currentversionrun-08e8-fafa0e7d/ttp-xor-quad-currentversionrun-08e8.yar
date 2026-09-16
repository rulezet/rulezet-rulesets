rule TTP_XOR_QUAD_CurrentVersionRun_08e8 {
  strings:
    $key_08e8 = { 5b 87 [2] 7f 89 [2] 54 a5 [2] 7a 87 [2] 6e 9c [2] 61 86 [2] 7f 9b [2] 7d 9a [2] 66 9c [2] 7a 9b [2] 66 b4 }

  condition:
    any of them
}