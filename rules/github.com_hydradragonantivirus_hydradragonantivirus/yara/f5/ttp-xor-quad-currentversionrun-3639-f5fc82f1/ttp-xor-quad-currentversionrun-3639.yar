rule TTP_XOR_QUAD_CurrentVersionRun_3639 {
  strings:
    $key_3639 = { 65 56 [2] 41 58 [2] 6a 74 [2] 44 56 [2] 50 4d [2] 5f 57 [2] 41 4a [2] 43 4b [2] 58 4d [2] 44 4a [2] 58 65 }

  condition:
    any of them
}