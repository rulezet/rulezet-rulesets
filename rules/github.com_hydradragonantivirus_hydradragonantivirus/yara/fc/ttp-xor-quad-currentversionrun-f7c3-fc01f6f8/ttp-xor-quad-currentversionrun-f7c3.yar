rule TTP_XOR_QUAD_CurrentVersionRun_f7c3 {
  strings:
    $key_f7c3 = { a4 ac [2] 80 a2 [2] ab 8e [2] 85 ac [2] 91 b7 [2] 9e ad [2] 80 b0 [2] 82 b1 [2] 99 b7 [2] 85 b0 [2] 99 9f }

  condition:
    any of them
}