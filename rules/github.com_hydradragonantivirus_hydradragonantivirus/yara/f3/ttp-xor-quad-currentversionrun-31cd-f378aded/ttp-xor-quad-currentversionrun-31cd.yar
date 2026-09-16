rule TTP_XOR_QUAD_CurrentVersionRun_31cd {
  strings:
    $key_31cd = { 62 a2 [2] 46 ac [2] 6d 80 [2] 43 a2 [2] 57 b9 [2] 58 a3 [2] 46 be [2] 44 bf [2] 5f b9 [2] 43 be [2] 5f 91 }

  condition:
    any of them
}