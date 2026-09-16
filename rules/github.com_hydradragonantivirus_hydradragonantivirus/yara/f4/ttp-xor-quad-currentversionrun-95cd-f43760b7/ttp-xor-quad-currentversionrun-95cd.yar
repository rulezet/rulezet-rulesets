rule TTP_XOR_QUAD_CurrentVersionRun_95cd {
  strings:
    $key_95cd = { c6 a2 [2] e2 ac [2] c9 80 [2] e7 a2 [2] f3 b9 [2] fc a3 [2] e2 be [2] e0 bf [2] fb b9 [2] e7 be [2] fb 91 }

  condition:
    any of them
}