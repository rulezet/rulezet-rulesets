rule TTP_XOR_QUAD_CurrentVersionRun_cedf {
  strings:
    $key_cedf = { 9d b0 [2] b9 be [2] 92 92 [2] bc b0 [2] a8 ab [2] a7 b1 [2] b9 ac [2] bb ad [2] a0 ab [2] bc ac [2] a0 83 }

  condition:
    any of them
}