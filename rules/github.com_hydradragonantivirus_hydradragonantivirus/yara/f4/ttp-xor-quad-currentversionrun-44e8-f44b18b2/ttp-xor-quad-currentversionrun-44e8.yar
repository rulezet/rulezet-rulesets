rule TTP_XOR_QUAD_CurrentVersionRun_44e8 {
  strings:
    $key_44e8 = { 17 87 [2] 33 89 [2] 18 a5 [2] 36 87 [2] 22 9c [2] 2d 86 [2] 33 9b [2] 31 9a [2] 2a 9c [2] 36 9b [2] 2a b4 }

  condition:
    any of them
}