rule TTP_XOR_QUAD_CurrentVersionRun_58e8 {
  strings:
    $key_58e8 = { 0b 87 [2] 2f 89 [2] 04 a5 [2] 2a 87 [2] 3e 9c [2] 31 86 [2] 2f 9b [2] 2d 9a [2] 36 9c [2] 2a 9b [2] 36 b4 }

  condition:
    any of them
}