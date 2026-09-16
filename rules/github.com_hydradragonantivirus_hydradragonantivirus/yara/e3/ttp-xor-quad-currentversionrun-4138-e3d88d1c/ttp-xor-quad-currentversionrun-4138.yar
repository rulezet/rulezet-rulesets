rule TTP_XOR_QUAD_CurrentVersionRun_4138 {
  strings:
    $key_4138 = { 12 57 [2] 36 59 [2] 1d 75 [2] 33 57 [2] 27 4c [2] 28 56 [2] 36 4b [2] 34 4a [2] 2f 4c [2] 33 4b [2] 2f 64 }

  condition:
    any of them
}