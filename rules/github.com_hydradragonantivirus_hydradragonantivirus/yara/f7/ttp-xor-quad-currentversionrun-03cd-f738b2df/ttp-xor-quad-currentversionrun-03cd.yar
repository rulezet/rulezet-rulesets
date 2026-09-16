rule TTP_XOR_QUAD_CurrentVersionRun_03cd {
  strings:
    $key_03cd = { 50 a2 [2] 74 ac [2] 5f 80 [2] 71 a2 [2] 65 b9 [2] 6a a3 [2] 74 be [2] 76 bf [2] 6d b9 [2] 71 be [2] 6d 91 }

  condition:
    any of them
}