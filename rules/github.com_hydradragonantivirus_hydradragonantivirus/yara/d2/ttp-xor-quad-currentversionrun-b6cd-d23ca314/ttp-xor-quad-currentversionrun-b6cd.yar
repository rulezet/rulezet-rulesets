rule TTP_XOR_QUAD_CurrentVersionRun_b6cd {
  strings:
    $key_b6cd = { e5 a2 [2] c1 ac [2] ea 80 [2] c4 a2 [2] d0 b9 [2] df a3 [2] c1 be [2] c3 bf [2] d8 b9 [2] c4 be [2] d8 91 }

  condition:
    any of them
}