rule TTP_XOR_QUAD_CurrentVersionRun_07e9 {
  strings:
    $key_07e9 = { 54 86 [2] 70 88 [2] 5b a4 [2] 75 86 [2] 61 9d [2] 6e 87 [2] 70 9a [2] 72 9b [2] 69 9d [2] 75 9a [2] 69 b5 }

  condition:
    any of them
}