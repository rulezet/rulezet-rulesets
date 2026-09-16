rule TTP_XOR_QUAD_CurrentVersionRun_4108 {
  strings:
    $key_4108 = { 12 67 [2] 36 69 [2] 1d 45 [2] 33 67 [2] 27 7c [2] 28 66 [2] 36 7b [2] 34 7a [2] 2f 7c [2] 33 7b [2] 2f 54 }

  condition:
    any of them
}