rule TTP_XOR_QUAD_CurrentVersionRun_d4cd {
  strings:
    $key_d4cd = { 87 a2 [2] a3 ac [2] 88 80 [2] a6 a2 [2] b2 b9 [2] bd a3 [2] a3 be [2] a1 bf [2] ba b9 [2] a6 be [2] ba 91 }

  condition:
    any of them
}