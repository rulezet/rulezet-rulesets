rule TTP_XOR_QUAD_CurrentVersionRun_73cd {
  strings:
    $key_73cd = { 20 a2 [2] 04 ac [2] 2f 80 [2] 01 a2 [2] 15 b9 [2] 1a a3 [2] 04 be [2] 06 bf [2] 1d b9 [2] 01 be [2] 1d 91 }

  condition:
    any of them
}