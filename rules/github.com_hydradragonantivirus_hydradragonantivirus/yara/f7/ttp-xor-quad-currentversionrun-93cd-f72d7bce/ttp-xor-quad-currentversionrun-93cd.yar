rule TTP_XOR_QUAD_CurrentVersionRun_93cd {
  strings:
    $key_93cd = { c0 a2 [2] e4 ac [2] cf 80 [2] e1 a2 [2] f5 b9 [2] fa a3 [2] e4 be [2] e6 bf [2] fd b9 [2] e1 be [2] fd 91 }

  condition:
    any of them
}