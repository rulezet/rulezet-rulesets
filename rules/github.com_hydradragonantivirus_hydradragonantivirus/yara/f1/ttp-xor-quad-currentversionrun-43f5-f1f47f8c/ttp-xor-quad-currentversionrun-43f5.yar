rule TTP_XOR_QUAD_CurrentVersionRun_43f5 {
  strings:
    $key_43f5 = { 10 9a [2] 34 94 [2] 1f b8 [2] 31 9a [2] 25 81 [2] 2a 9b [2] 34 86 [2] 36 87 [2] 2d 81 [2] 31 86 [2] 2d a9 }

  condition:
    any of them
}