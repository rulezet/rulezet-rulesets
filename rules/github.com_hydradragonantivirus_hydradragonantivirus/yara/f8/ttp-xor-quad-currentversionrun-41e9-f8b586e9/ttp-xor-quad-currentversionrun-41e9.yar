rule TTP_XOR_QUAD_CurrentVersionRun_41e9 {
  strings:
    $key_41e9 = { 12 86 [2] 36 88 [2] 1d a4 [2] 33 86 [2] 27 9d [2] 28 87 [2] 36 9a [2] 34 9b [2] 2f 9d [2] 33 9a [2] 2f b5 }

  condition:
    any of them
}