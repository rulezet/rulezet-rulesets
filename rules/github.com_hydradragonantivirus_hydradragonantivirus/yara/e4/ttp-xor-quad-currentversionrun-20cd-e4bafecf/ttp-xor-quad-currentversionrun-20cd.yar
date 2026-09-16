rule TTP_XOR_QUAD_CurrentVersionRun_20cd {
  strings:
    $key_20cd = { 73 a2 [2] 57 ac [2] 7c 80 [2] 52 a2 [2] 46 b9 [2] 49 a3 [2] 57 be [2] 55 bf [2] 4e b9 [2] 52 be [2] 4e 91 }

  condition:
    any of them
}