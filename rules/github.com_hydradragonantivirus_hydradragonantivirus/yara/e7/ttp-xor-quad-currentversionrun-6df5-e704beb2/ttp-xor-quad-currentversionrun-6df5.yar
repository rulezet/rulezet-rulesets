rule TTP_XOR_QUAD_CurrentVersionRun_6df5 {
  strings:
    $key_6df5 = { 3e 9a [2] 1a 94 [2] 31 b8 [2] 1f 9a [2] 0b 81 [2] 04 9b [2] 1a 86 [2] 18 87 [2] 03 81 [2] 1f 86 [2] 03 a9 }

  condition:
    any of them
}