rule TTP_XOR_QUAD_CurrentVersionRun_4608 {
  strings:
    $key_4608 = { 15 67 [2] 31 69 [2] 1a 45 [2] 34 67 [2] 20 7c [2] 2f 66 [2] 31 7b [2] 33 7a [2] 28 7c [2] 34 7b [2] 28 54 }

  condition:
    any of them
}