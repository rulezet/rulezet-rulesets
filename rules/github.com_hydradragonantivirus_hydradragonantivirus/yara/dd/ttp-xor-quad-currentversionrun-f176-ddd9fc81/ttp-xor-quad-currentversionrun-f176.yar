rule TTP_XOR_QUAD_CurrentVersionRun_f176 {
  strings:
    $key_f176 = { a2 19 [2] 86 17 [2] ad 3b [2] 83 19 [2] 97 02 [2] 98 18 [2] 86 05 [2] 84 04 [2] 9f 02 [2] 83 05 [2] 9f 2a }

  condition:
    any of them
}