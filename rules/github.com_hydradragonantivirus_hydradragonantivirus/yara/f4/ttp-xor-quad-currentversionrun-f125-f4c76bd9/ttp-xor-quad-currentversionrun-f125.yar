rule TTP_XOR_QUAD_CurrentVersionRun_f125 {
  strings:
    $key_f125 = { a2 4a [2] 86 44 [2] ad 68 [2] 83 4a [2] 97 51 [2] 98 4b [2] 86 56 [2] 84 57 [2] 9f 51 [2] 83 56 [2] 9f 79 }

  condition:
    any of them
}