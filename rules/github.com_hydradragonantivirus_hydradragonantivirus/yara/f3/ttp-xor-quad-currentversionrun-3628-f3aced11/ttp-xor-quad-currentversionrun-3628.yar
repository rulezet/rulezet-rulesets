rule TTP_XOR_QUAD_CurrentVersionRun_3628 {
  strings:
    $key_3628 = { 65 47 [2] 41 49 [2] 6a 65 [2] 44 47 [2] 50 5c [2] 5f 46 [2] 41 5b [2] 43 5a [2] 58 5c [2] 44 5b [2] 58 74 }

  condition:
    any of them
}