rule TTP_XOR_QUAD_CurrentVersionRun_f196 {
  strings:
    $key_f196 = { a2 f9 [2] 86 f7 [2] ad db [2] 83 f9 [2] 97 e2 [2] 98 f8 [2] 86 e5 [2] 84 e4 [2] 9f e2 [2] 83 e5 [2] 9f ca }

  condition:
    any of them
}