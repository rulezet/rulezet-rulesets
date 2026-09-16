rule TTP_XOR_QUAD_CurrentVersionRun_93d0 {
  strings:
    $key_93d0 = { c0 bf [2] e4 b1 [2] cf 9d [2] e1 bf [2] f5 a4 [2] fa be [2] e4 a3 [2] e6 a2 [2] fd a4 [2] e1 a3 [2] fd 8c }

  condition:
    any of them
}