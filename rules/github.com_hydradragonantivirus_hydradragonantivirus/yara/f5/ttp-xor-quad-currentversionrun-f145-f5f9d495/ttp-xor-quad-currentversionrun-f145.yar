rule TTP_XOR_QUAD_CurrentVersionRun_f145 {
  strings:
    $key_f145 = { a2 2a [2] 86 24 [2] ad 08 [2] 83 2a [2] 97 31 [2] 98 2b [2] 86 36 [2] 84 37 [2] 9f 31 [2] 83 36 [2] 9f 19 }

  condition:
    any of them
}