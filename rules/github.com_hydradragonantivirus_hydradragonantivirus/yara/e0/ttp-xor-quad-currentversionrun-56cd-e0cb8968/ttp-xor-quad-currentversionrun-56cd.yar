rule TTP_XOR_QUAD_CurrentVersionRun_56cd {
  strings:
    $key_56cd = { 05 a2 [2] 21 ac [2] 0a 80 [2] 24 a2 [2] 30 b9 [2] 3f a3 [2] 21 be [2] 23 bf [2] 38 b9 [2] 24 be [2] 38 91 }

  condition:
    any of them
}