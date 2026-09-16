rule TTP_XOR_QUAD_CurrentVersionRun_36cd {
  strings:
    $key_36cd = { 65 a2 [2] 41 ac [2] 6a 80 [2] 44 a2 [2] 50 b9 [2] 5f a3 [2] 41 be [2] 43 bf [2] 58 b9 [2] 44 be [2] 58 91 }

  condition:
    any of them
}