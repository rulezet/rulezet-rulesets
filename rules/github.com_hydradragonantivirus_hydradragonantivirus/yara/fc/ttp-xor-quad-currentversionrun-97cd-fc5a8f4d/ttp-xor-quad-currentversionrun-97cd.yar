rule TTP_XOR_QUAD_CurrentVersionRun_97cd {
  strings:
    $key_97cd = { c4 a2 [2] e0 ac [2] cb 80 [2] e5 a2 [2] f1 b9 [2] fe a3 [2] e0 be [2] e2 bf [2] f9 b9 [2] e5 be [2] f9 91 }

  condition:
    any of them
}