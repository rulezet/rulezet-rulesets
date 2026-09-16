rule TTP_XOR_QUAD_CurrentVersionRun_97d0 {
  strings:
    $key_97d0 = { c4 bf [2] e0 b1 [2] cb 9d [2] e5 bf [2] f1 a4 [2] fe be [2] e0 a3 [2] e2 a2 [2] f9 a4 [2] e5 a3 [2] f9 8c }

  condition:
    any of them
}