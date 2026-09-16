rule TTP_XOR_QUAD_CurrentVersionRun_51cd {
  strings:
    $key_51cd = { 02 a2 [2] 26 ac [2] 0d 80 [2] 23 a2 [2] 37 b9 [2] 38 a3 [2] 26 be [2] 24 bf [2] 3f b9 [2] 23 be [2] 3f 91 }

  condition:
    any of them
}