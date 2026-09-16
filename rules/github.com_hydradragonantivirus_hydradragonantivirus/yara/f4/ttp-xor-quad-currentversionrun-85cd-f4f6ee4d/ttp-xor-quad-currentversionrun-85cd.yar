rule TTP_XOR_QUAD_CurrentVersionRun_85cd {
  strings:
    $key_85cd = { d6 a2 [2] f2 ac [2] d9 80 [2] f7 a2 [2] e3 b9 [2] ec a3 [2] f2 be [2] f0 bf [2] eb b9 [2] f7 be [2] eb 91 }

  condition:
    any of them
}