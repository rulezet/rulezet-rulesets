rule TTP_XOR_QUAD_CurrentVersionRun_dfcd {
  strings:
    $key_dfcd = { 8c a2 [2] a8 ac [2] 83 80 [2] ad a2 [2] b9 b9 [2] b6 a3 [2] a8 be [2] aa bf [2] b1 b9 [2] ad be [2] b1 91 }

  condition:
    any of them
}