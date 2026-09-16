rule TTP_XOR_QUAD_CurrentVersionRun_242b {
  strings:
    $key_242b = { 77 44 [2] 53 4a [2] 78 66 [2] 56 44 [2] 42 5f [2] 4d 45 [2] 53 58 [2] 51 59 [2] 4a 5f [2] 56 58 [2] 4a 77 }

  condition:
    any of them
}