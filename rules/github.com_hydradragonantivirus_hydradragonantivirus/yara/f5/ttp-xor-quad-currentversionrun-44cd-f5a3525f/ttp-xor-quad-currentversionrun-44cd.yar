rule TTP_XOR_QUAD_CurrentVersionRun_44cd {
  strings:
    $key_44cd = { 17 a2 [2] 33 ac [2] 18 80 [2] 36 a2 [2] 22 b9 [2] 2d a3 [2] 33 be [2] 31 bf [2] 2a b9 [2] 36 be [2] 2a 91 }

  condition:
    any of them
}