rule TTP_XOR_QUAD_CurrentVersionRun_e6c3 {
  strings:
    $key_e6c3 = { b5 ac [2] 91 a2 [2] ba 8e [2] 94 ac [2] 80 b7 [2] 8f ad [2] 91 b0 [2] 93 b1 [2] 88 b7 [2] 94 b0 [2] 88 9f }

  condition:
    any of them
}