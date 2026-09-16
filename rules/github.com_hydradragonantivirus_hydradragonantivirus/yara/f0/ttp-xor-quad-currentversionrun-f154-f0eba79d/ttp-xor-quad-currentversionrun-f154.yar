rule TTP_XOR_QUAD_CurrentVersionRun_f154 {
  strings:
    $key_f154 = { a2 3b [2] 86 35 [2] ad 19 [2] 83 3b [2] 97 20 [2] 98 3a [2] 86 27 [2] 84 26 [2] 9f 20 [2] 83 27 [2] 9f 08 }

  condition:
    any of them
}