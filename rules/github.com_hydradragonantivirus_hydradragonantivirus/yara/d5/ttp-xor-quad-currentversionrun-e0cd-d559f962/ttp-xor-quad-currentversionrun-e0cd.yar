rule TTP_XOR_QUAD_CurrentVersionRun_e0cd {
  strings:
    $key_e0cd = { b3 a2 [2] 97 ac [2] bc 80 [2] 92 a2 [2] 86 b9 [2] 89 a3 [2] 97 be [2] 95 bf [2] 8e b9 [2] 92 be [2] 8e 91 }

  condition:
    any of them
}