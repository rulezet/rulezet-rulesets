rule TTP_XOR_QUAD_CurrentVersionRun_36e8 {
  strings:
    $key_36e8 = { 65 87 [2] 41 89 [2] 6a a5 [2] 44 87 [2] 50 9c [2] 5f 86 [2] 41 9b [2] 43 9a [2] 58 9c [2] 44 9b [2] 58 b4 }

  condition:
    any of them
}