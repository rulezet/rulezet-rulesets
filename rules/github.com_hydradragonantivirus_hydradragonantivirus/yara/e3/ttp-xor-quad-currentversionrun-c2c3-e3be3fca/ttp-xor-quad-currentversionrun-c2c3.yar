rule TTP_XOR_QUAD_CurrentVersionRun_c2c3 {
  strings:
    $key_c2c3 = { 91 ac [2] b5 a2 [2] 9e 8e [2] b0 ac [2] a4 b7 [2] ab ad [2] b5 b0 [2] b7 b1 [2] ac b7 [2] b0 b0 [2] ac 9f }

  condition:
    any of them
}