rule TTP_XOR_QUAD_CurrentVersionRun_f139 {
  strings:
    $key_f139 = { a2 56 [2] 86 58 [2] ad 74 [2] 83 56 [2] 97 4d [2] 98 57 [2] 86 4a [2] 84 4b [2] 9f 4d [2] 83 4a [2] 9f 65 }

  condition:
    any of them
}