rule TTP_XOR_QUAD_CurrentVersionRun_35cd {
  strings:
    $key_35cd = { 66 a2 [2] 42 ac [2] 69 80 [2] 47 a2 [2] 53 b9 [2] 5c a3 [2] 42 be [2] 40 bf [2] 5b b9 [2] 47 be [2] 5b 91 }

  condition:
    any of them
}