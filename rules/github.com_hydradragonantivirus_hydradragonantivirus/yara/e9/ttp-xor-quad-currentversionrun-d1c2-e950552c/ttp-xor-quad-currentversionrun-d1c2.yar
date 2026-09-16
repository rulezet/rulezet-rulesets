rule TTP_XOR_QUAD_CurrentVersionRun_d1c2 {
  strings:
    $key_d1c2 = { 82 ad [2] a6 a3 [2] 8d 8f [2] a3 ad [2] b7 b6 [2] b8 ac [2] a6 b1 [2] a4 b0 [2] bf b6 [2] a3 b1 [2] bf 9e }

  condition:
    any of them
}