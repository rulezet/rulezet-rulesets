rule TTP_XOR_QUAD_CurrentVersionRun_f123 {
  strings:
    $key_f123 = { a2 4c [2] 86 42 [2] ad 6e [2] 83 4c [2] 97 57 [2] 98 4d [2] 86 50 [2] 84 51 [2] 9f 57 [2] 83 50 [2] 9f 7f }

  condition:
    any of them
}