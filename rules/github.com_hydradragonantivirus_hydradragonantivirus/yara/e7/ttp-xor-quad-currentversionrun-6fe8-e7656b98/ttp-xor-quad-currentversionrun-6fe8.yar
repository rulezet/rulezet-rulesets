rule TTP_XOR_QUAD_CurrentVersionRun_6fe8 {
  strings:
    $key_6fe8 = { 3c 87 [2] 18 89 [2] 33 a5 [2] 1d 87 [2] 09 9c [2] 06 86 [2] 18 9b [2] 1a 9a [2] 01 9c [2] 1d 9b [2] 01 b4 }

  condition:
    any of them
}