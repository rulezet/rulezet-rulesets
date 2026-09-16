rule TTP_XOR_QUAD_CurrentVersionRun_cbdf {
  strings:
    $key_cbdf = { 98 b0 [2] bc be [2] 97 92 [2] b9 b0 [2] ad ab [2] a2 b1 [2] bc ac [2] be ad [2] a5 ab [2] b9 ac [2] a5 83 }

  condition:
    any of them
}