rule TTP_XOR_QUAD_CurrentVersionRun_04cd {
  strings:
    $key_04cd = { 57 a2 [2] 73 ac [2] 58 80 [2] 76 a2 [2] 62 b9 [2] 6d a3 [2] 73 be [2] 71 bf [2] 6a b9 [2] 76 be [2] 6a 91 }

  condition:
    any of them
}