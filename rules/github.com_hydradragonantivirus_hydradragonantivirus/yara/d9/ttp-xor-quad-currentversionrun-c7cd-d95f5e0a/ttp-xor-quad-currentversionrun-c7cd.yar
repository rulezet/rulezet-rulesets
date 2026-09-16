rule TTP_XOR_QUAD_CurrentVersionRun_c7cd {
  strings:
    $key_c7cd = { 94 a2 [2] b0 ac [2] 9b 80 [2] b5 a2 [2] a1 b9 [2] ae a3 [2] b0 be [2] b2 bf [2] a9 b9 [2] b5 be [2] a9 91 }

  condition:
    any of them
}