rule TTP_XOR_QUAD_CurrentVersionRun_91cd {
  strings:
    $key_91cd = { c2 a2 [2] e6 ac [2] cd 80 [2] e3 a2 [2] f7 b9 [2] f8 a3 [2] e6 be [2] e4 bf [2] ff b9 [2] e3 be [2] ff 91 }

  condition:
    any of them
}