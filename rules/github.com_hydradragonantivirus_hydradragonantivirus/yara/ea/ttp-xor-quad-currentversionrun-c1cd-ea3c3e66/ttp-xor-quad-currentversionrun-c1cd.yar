rule TTP_XOR_QUAD_CurrentVersionRun_c1cd {
  strings:
    $key_c1cd = { 92 a2 [2] b6 ac [2] 9d 80 [2] b3 a2 [2] a7 b9 [2] a8 a3 [2] b6 be [2] b4 bf [2] af b9 [2] b3 be [2] af 91 }

  condition:
    any of them
}