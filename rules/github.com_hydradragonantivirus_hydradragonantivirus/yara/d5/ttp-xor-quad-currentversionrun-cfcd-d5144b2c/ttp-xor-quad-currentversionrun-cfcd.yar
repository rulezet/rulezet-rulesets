rule TTP_XOR_QUAD_CurrentVersionRun_cfcd {
  strings:
    $key_cfcd = { 9c a2 [2] b8 ac [2] 93 80 [2] bd a2 [2] a9 b9 [2] a6 a3 [2] b8 be [2] ba bf [2] a1 b9 [2] bd be [2] a1 91 }

  condition:
    any of them
}