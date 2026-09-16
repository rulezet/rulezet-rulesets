rule TTP_XOR_QUAD_CurrentVersionRun_cecd {
  strings:
    $key_cecd = { 9d a2 [2] b9 ac [2] 92 80 [2] bc a2 [2] a8 b9 [2] a7 a3 [2] b9 be [2] bb bf [2] a0 b9 [2] bc be [2] a0 91 }

  condition:
    any of them
}