rule TTP_XOR_QUAD_CurrentVersionRun_f5cd {
  strings:
    $key_f5cd = { a6 a2 [2] 82 ac [2] a9 80 [2] 87 a2 [2] 93 b9 [2] 9c a3 [2] 82 be [2] 80 bf [2] 9b b9 [2] 87 be [2] 9b 91 }

  condition:
    any of them
}