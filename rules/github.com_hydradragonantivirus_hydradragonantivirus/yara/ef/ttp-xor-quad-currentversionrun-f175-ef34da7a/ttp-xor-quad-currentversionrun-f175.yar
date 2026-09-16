rule TTP_XOR_QUAD_CurrentVersionRun_f175 {
  strings:
    $key_f175 = { a2 1a [2] 86 14 [2] ad 38 [2] 83 1a [2] 97 01 [2] 98 1b [2] 86 06 [2] 84 07 [2] 9f 01 [2] 83 06 [2] 9f 29 }

  condition:
    any of them
}