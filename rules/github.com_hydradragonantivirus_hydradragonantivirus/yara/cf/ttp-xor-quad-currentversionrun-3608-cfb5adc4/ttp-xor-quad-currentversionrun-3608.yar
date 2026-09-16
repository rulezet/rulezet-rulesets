rule TTP_XOR_QUAD_CurrentVersionRun_3608 {
  strings:
    $key_3608 = { 65 67 [2] 41 69 [2] 6a 45 [2] 44 67 [2] 50 7c [2] 5f 66 [2] 41 7b [2] 43 7a [2] 58 7c [2] 44 7b [2] 58 54 }

  condition:
    any of them
}