rule TTP_XOR_QUAD_CurrentVersionRun_52cd {
  strings:
    $key_52cd = { 01 a2 [2] 25 ac [2] 0e 80 [2] 20 a2 [2] 34 b9 [2] 3b a3 [2] 25 be [2] 27 bf [2] 3c b9 [2] 20 be [2] 3c 91 }

  condition:
    any of them
}