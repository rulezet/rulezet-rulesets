rule TTP_XOR_QUAD_CurrentVersionRun_f158 {
  strings:
    $key_f158 = { a2 37 [2] 86 39 [2] ad 15 [2] 83 37 [2] 97 2c [2] 98 36 [2] 86 2b [2] 84 2a [2] 9f 2c [2] 83 2b [2] 9f 04 }

  condition:
    any of them
}