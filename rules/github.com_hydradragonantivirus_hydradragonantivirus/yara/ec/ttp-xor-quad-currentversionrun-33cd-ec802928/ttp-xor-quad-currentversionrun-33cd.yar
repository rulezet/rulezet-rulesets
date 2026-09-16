rule TTP_XOR_QUAD_CurrentVersionRun_33cd {
  strings:
    $key_33cd = { 60 a2 [2] 44 ac [2] 6f 80 [2] 41 a2 [2] 55 b9 [2] 5a a3 [2] 44 be [2] 46 bf [2] 5d b9 [2] 41 be [2] 5d 91 }

  condition:
    any of them
}